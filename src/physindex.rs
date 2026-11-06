//! Physical memory index: maps a page-aligned [`Gpa`] to the file offset where
//! the content of that page lives. Sorted runs of consecutive pages (full,
//! kernel and complete dumps) or the dump bitmap plus a rank table (bitmap
//! dumps). Memory grows with the number of runs or with the size of the
//! bitmap instead of with the number of pages.
use std::num::NonZeroU64;
use std::ops::Range;

use crate::error::{Error, Result};
use crate::gxa::Gpa;
use crate::pxe::Pfn;
use crate::structs::PageKind;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct Run {
    first_pfn: Pfn,
    pages: u64,
    file_offset: u64,
}

impl Run {
    pub(crate) fn pfn_range(&self) -> Range<Pfn> {
        let start = self.first_pfn;
        let end = start + self.pages;
        debug_assert!(end > start);

        start..end
    }

    pub(crate) fn file_offset_range(&self) -> Range<u64> {
        let start = self.file_offset;
        let len = self.pages * PageKind::Normal.len();
        let end = start + len;
        debug_assert!(end > start);

        start..end
    }

    pub(crate) fn is_contiguous_after(&self, other: &Run) -> bool {
        // For two runs to be contiguous, they need to have contiguous physical
        // addresses as well as being stored in the dump file with contiguous
        // file offsets.
        self.pfn_range().start == other.pfn_range().end
            && self.file_offset_range().start == other.file_offset_range().end
    }

    pub(crate) fn file_offset_for_pfn(&self, pfn: Pfn) -> Option<u64> {
        let page_index = pfn.u64().checked_sub(self.first_pfn.u64())?;
        if page_index >= self.pages {
            return None;
        }

        let offset_from_run = page_index.checked_mul(PageKind::Normal.len())?;

        self.file_offset.checked_add(offset_from_run)
    }
}

/// Collects pages in file order; coalesces consecutive pages into runs.
pub(crate) struct Builder {
    runs: Vec<Run>,
}

impl Builder {
    pub fn new() -> Self {
        Self { runs: Vec::new() }
    }

    /// Records a page.
    pub fn push(&mut self, gpa: Gpa, file_offset: u64) {
        let pfn = gpa.pfn();
        let run = Run {
            first_pfn: pfn,
            pages: 1,
            file_offset,
        };

        // Try to merge this page w/ the last run we added if it contiguous with
        // this page..
        if let Some(last) = self.runs.last_mut()
            && run.is_contiguous_after(last)
        {
            last.pages += 1;
        }
        // Otherwise simply create a new run with 1 page.
        else {
            self.runs.push(Run {
                first_pfn: pfn,
                pages: 1,
                file_offset,
            });
        }
    }

    /// Records `pages` consecutive pages starting at `gpa` whose contents are
    /// stored back to back from `file_offset`.
    pub fn push_run(&mut self, gpa: Gpa, pages: NonZeroU64, file_offset: u64) {
        self.push(gpa, file_offset);
        // SAFETY: We can `unwrap` here unconditionally because after the `push`
        // we have at least one runs available.
        let last = self.runs.last_mut().unwrap();
        // The `push` call increased or set the `pages` to 1, so deduct it.
        let pages = pages.get() - 1;
        last.pages += pages;
    }

    /// Finalizes the index.
    pub fn finish(mut self) -> Result<PhysIndex> {
        // Sort the runs.. (we don't care if elements that are equal are
        // re-ordered, so unstability is fine)..
        self.runs.sort_unstable_by_key(|r| r.first_pfn);

        // Detect duplicate gpas / overlaped runs..
        for [run, next_run] in self.runs.array_windows::<2>() {
            if run.pfn_range().end > next_run.pfn_range().start {
                return Err(Error::InvalidData("duplicate gpa in phys index"));
            }
        }

        // Merge every runs we can..
        self.runs.dedup_by(|next, prev| {
            // If `next` is contiguous after `p`, then let's merge `next` into
            // `prev`..
            if next.is_contiguous_after(prev) {
                prev.pages += next.pages;

                // ..and delete `next`.
                true
            }
            // Otherwise keep both runs.
            else {
                false
            }
        });

        // ..and shrink the vec.
        self.runs.shrink_to_fit();

        Ok(PhysIndex { runs: self.runs })
    }
}

pub(crate) struct PhysIndex {
    runs: Vec<Run>,
}

impl PhysIndex {
    /// File offset of the page at `page`, if the dump has it.
    pub fn get(&self, page: Gpa) -> Option<u64> {
        // Find the index of the first run that starts at a pfn greater
        // than the one we're looking for. We partition
        // the runs in two; the left side has runs that starts at a pfn
        // smaller or equal, and the right one has runs
        // that start w/ a greater pfn.
        //
        // For example, the `partition_idx` would be:
        //  - `0` if `pfn` was `1`
        //  - `2` if `pfn` was `6`
        //  - `3` if `pfn` was `11`
        //
        // Runs: `[start: 2, end: 5], [start: 5, end: 6], [start: 10,
        // end: 14]`
        let pfn = page.pfn();
        let partition_idx = self.runs.partition_point(|r| r.pfn_range().start <= pfn);

        // The partition idx is the first item that has a larger start
        // pfn.. which means that our `pfn` is inside the run right
        // before, so we're done.
        if partition_idx == 0 {
            return None;
        }

        // This run is the one that potentially includes the `pfn` we're
        // after. It is possible to end up in a case like index `2` for
        // the pfn `6` in the above example. The pfn `6` is actually in
        // a hole in between the two sides of the partition.
        let run = self.runs[partition_idx - 1];

        // Get the file offset if the run actuall this pfn.
        run.file_offset_for_pfn(pfn)
    }

    /// Iterates over (page, file offset) pairs in ascending page order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (Gpa, u64)> {
        PhysIter::new(&self.runs)
    }
}

/// Iterator over (page, file offset) pairs with an exact length.
pub(crate) struct PhysIter<'runs> {
    runs: &'runs [Run],
    cur_pfn: Pfn,
    left: usize,
}

impl<'runs> PhysIter<'runs> {
    pub(crate) fn new(runs: &'runs [Run]) -> Self {
        let left = runs.iter().map(|r| usize::try_from(r.pages).unwrap()).sum();
        let cur_pfn = runs.first().map_or(Pfn::new(0), |r| r.pfn_range().start);

        Self {
            runs,
            cur_pfn,
            left,
        }
    }
}

impl Iterator for PhysIter<'_> {
    type Item = (Gpa, u64);

    fn next(&mut self) -> Option<Self::Item> {
        // If we walked through every pages, we're done.
        if self.left == 0 {
            return None;
        }

        // Because `self.left` is > 0, this is safe to assume we still have at
        // least one more run left. We need to figure out if we need to
        // move to the next run though..
        if self.runs[0].file_offset_for_pfn(self.cur_pfn).is_none() {
            // ..if so, we remove the first one..
            self.runs = &self.runs[1..];
            // ..and we start from this new run's start pfn.
            self.cur_pfn = self.runs[0].pfn_range().start;
        }

        let pfn = self.cur_pfn;
        // This is safe because 1) either we got into the if block above and we
        // set `self.cur_pfn` to the first pfn of the run, or 2) we didn't get
        // into the block in which case it worked before.
        let file_offset = self.runs[0].file_offset_for_pfn(pfn).unwrap();

        // Move the pfn along, as well as keeping track of how many more times
        // we need to yield.
        self.cur_pfn = Pfn::new(self.cur_pfn.u64() + 1);
        self.left -= 1;

        Some((pfn.gpa(), file_offset))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for PhysIter<'_> {}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::error::Error;
    use crate::gxa::Gpa;
    use crate::physindex::{Builder, PhysIndex, Run};

    fn assert_runs(builder: Builder, expected: &[Run]) {
        let PhysIndex { runs } = builder.finish().unwrap();

        assert_eq!(runs.len(), expected.len());
        assert_eq!(
            runs.iter().map(|r| r.pages).sum::<u64>(),
            expected.iter().map(|e| e.pages).sum()
        );

        for (run, expected) in runs.iter().zip(expected) {
            assert_eq!(run, expected);
        }
    }

    fn run(gpa: u64, pages: u64, file_offset: u64) -> Run {
        Run {
            first_pfn: Gpa::new(gpa).pfn(),
            pages,
            file_offset,
        }
    }

    fn builder(runs: &[Run]) -> Builder {
        let mut builder = Builder::new();
        for run in runs {
            builder.push_run(
                Gpa::from_pfn(run.first_pfn),
                NonZeroU64::new(run.pages).unwrap(),
                run.file_offset,
            );
        }

        builder
    }

    #[test]
    fn empty_and_single_page() {
        assert_runs(builder(&[]), &[]);

        let builder = builder(&[run(0, 1, 0)]);

        assert_runs(builder, &[run(0, 1, 0)]);
    }

    #[test]
    fn merge_runs() {
        let builder = builder(&[
            run(0x1_000, 1, 0),
            run(0x2_000, 1, 0x1_000),
            run(0x3_000, 3, 0x2_000),
            run(0x6_000, 1, 0x5_000),
        ]);

        assert_runs(builder, &[run(0x1_000, 6, 0)]);
    }

    #[test]
    fn merge_out_of_order_runs() {
        let builder = builder(&[
            run(0x3_000, 2, 0x2_000),
            run(0x1_000, 2, 0),
            run(0x5_000, 2, 0x4_000),
        ]);

        assert_runs(builder, &[run(0x1_000, 6, 0)]);
    }

    #[test]
    fn sorts_runs_but_no_merge_across_gaps() {
        let builder = builder(&[
            run(0x4_000, 2, 0x5_000),
            run(0x1_000, 2, 0),
            // 0x1_000-0x2_000 are adjacent GPAs, but not in the offset space
            // where's a gap of a page.
            run(0x3_000, 1, 0x3_000),
        ]);

        assert_runs(builder, &[
            run(0x1_000, 2, 0),
            run(0x3_000, 1, 0x3_000),
            run(0x4_000, 2, 0x5_000),
        ]);
    }

    #[test]
    fn rejects_duplicates_and_overlaps() {
        // Exact dup.
        let exact_dup = [run(0x1_000, 1, 0), run(0x1_000, 1, 0)];
        assert!(matches!(
            builder(&exact_dup).finish(),
            Err(Error::InvalidData(_))
        ));

        // First range fully includes the second one.
        let mut full_inc = [run(0x1_000, 5, 0), run(0x2_000, 2, 0x1_000)];
        assert!(matches!(
            builder(&full_inc).finish(),
            Err(Error::InvalidData(_))
        ));

        // Same as above but reversed order.
        full_inc.reverse();
        assert!(matches!(
            builder(&full_inc).finish(),
            Err(Error::InvalidData(_))
        ));

        // Partial overlap.
        let partial_overlap = [run(0x1_000, 5, 0), run(0x5_000, 2, 0x1_000)];

        assert!(matches!(
            builder(&partial_overlap).finish(),
            Err(Error::InvalidData(_))
        ));
    }
}
