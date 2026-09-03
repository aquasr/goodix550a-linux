//! Enrollment registration acceptance policy.

pub const GF3258_REGISTRATION_SCORE_STRONG: i32 = 216;
pub const GF3258_REGISTRATION_SCORE_WEAK: i32 = 209;
pub const GF3258_REGISTRATION_VALIDITY_MIN: i32 = 65;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gf3258RegistrationDecision {
    Reject,
    Accept,
}

/// Exact final acceptance thresholds in FUN_001ba520 after geometric matching.
pub fn gf3258_registration_accepts(
    geometric_inliers: usize,
    metric_a: i32,
    metric_b: i32,
) -> Gf3258RegistrationDecision {
    let accept = match geometric_inliers {
        0..=5 => false,
        6 => metric_a >= GF3258_REGISTRATION_SCORE_STRONG,
        7..=10 => {
            metric_a >= GF3258_REGISTRATION_SCORE_STRONG
                || (metric_a >= GF3258_REGISTRATION_SCORE_WEAK
                    && metric_b >= GF3258_REGISTRATION_VALIDITY_MIN)
        }
        _ => true,
    };

    if accept {
        Gf3258RegistrationDecision::Accept
    } else {
        Gf3258RegistrationDecision::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_threshold_table_is_exact() {
        assert_eq!(
            gf3258_registration_accepts(5, 255, 255),
            Gf3258RegistrationDecision::Reject
        );
        assert_eq!(
            gf3258_registration_accepts(6, 215, 255),
            Gf3258RegistrationDecision::Reject
        );
        assert_eq!(
            gf3258_registration_accepts(6, 216, 0),
            Gf3258RegistrationDecision::Accept
        );
        assert_eq!(
            gf3258_registration_accepts(7, 209, 64),
            Gf3258RegistrationDecision::Reject
        );
        assert_eq!(
            gf3258_registration_accepts(7, 209, 65),
            Gf3258RegistrationDecision::Accept
        );
        assert_eq!(
            gf3258_registration_accepts(11, 0, 0),
            Gf3258RegistrationDecision::Accept
        );
    }
}
