//! Canonical pair-relation storage and directional access.

use super::Gf3258AffineQ8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf3258PairRelation {
    /// -1 absent; >5 direct geometric support; 2 synthesized by final closure.
    pub relation_value: i32,
    /// Canonical storage direction is higher sample index -> lower sample index.
    pub transform_higher_to_lower: Gf3258AffineQ8,
}

impl Default for Gf3258PairRelation {
    fn default() -> Self {
        Self {
            relation_value: -1,
            transform_higher_to_lower: Gf3258AffineQ8::IDENTITY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gf3258PairRelationTable {
    sample_capacity: usize,
    records: Vec<Gf3258PairRelation>,
}

impl Gf3258PairRelationTable {
    pub fn new(sample_capacity: usize) -> Self {
        Self {
            sample_capacity,
            records: vec![
                Gf3258PairRelation::default();
                sample_capacity.saturating_mul(sample_capacity.saturating_sub(1)) / 2
            ],
        }
    }

    #[inline]
    pub fn row_base(high: usize) -> usize {
        high * high.saturating_sub(1) / 2
    }

    fn index(&self, a: usize, b: usize) -> Option<usize> {
        if a == b || a >= self.sample_capacity || b >= self.sample_capacity {
            return None;
        }
        let high = a.max(b);
        let low = a.min(b);
        Some(Self::row_base(high) + low)
    }

    pub fn canonical_record(&self, a: usize, b: usize) -> Option<Gf3258PairRelation> {
        self.index(a, b).map(|index| self.records[index])
    }

    pub fn set_canonical_record(
        &mut self,
        a: usize,
        b: usize,
        relation: Gf3258PairRelation,
    ) -> bool {
        let Some(index) = self.index(a, b) else {
            return false;
        };
        self.records[index] = relation;
        true
    }

    /// Read-mode semantics of FUN_001abc10 for ordinary samples: return the
    /// transform `source -> target`, independent of triangular storage order.
    pub fn relation_source_to_target(
        &self,
        target: usize,
        source: usize,
    ) -> Option<(i32, Gf3258AffineQ8)> {
        let record = self.canonical_record(target, source)?;
        let transform = if source > target {
            record.transform_higher_to_lower
        } else {
            record.transform_higher_to_lower.inverse()
        };
        Some((record.relation_value, transform))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_table_normalizes_read_direction() {
        let mut table = Gf3258PairRelationTable::new(4);
        let high_to_low = Gf3258AffineQ8 {
            tx: -0x100,
            ..Gf3258AffineQ8::IDENTITY
        };
        assert!(table.set_canonical_record(
            0,
            2,
            Gf3258PairRelation {
                relation_value: 9,
                transform_higher_to_lower: high_to_low
            },
        ));
        assert_eq!(
            table.relation_source_to_target(0, 2),
            Some((9, high_to_low))
        );
        assert_eq!(
            table.relation_source_to_target(2, 0),
            Some((9, high_to_low.inverse()))
        );
    }
}
