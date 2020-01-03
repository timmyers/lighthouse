//! Extension trace macro which can be enabled at compile time with the feature `trace_ext`.
#[macro_export]

macro_rules! trace_ext (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        #[cfg(feature = "trace_ext")]
        trace!($l, $tag, $($args)+)
    };
    ($l:expr, $($args:tt)+) => {
        #[cfg(feature = "trace_ext")]
        trace!($l, $($args)+)
    };
);
