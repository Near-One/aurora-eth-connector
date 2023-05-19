use aurora_engine_types::str::from_utf8;
use near_sdk::env::panic_str;

const INVALID_UTF8_ERR_STRING: &str = "INVALID_UTF8_ERR_STRING";

#[macro_export]
macro_rules! log {
    ($($args:tt)*) => {
        #[cfg(feature = "log")]
        near_sdk::log!(&aurora_engine_types::format!("{}", format_args!($($args)*)))
    };
}

/// Panic with the message from the error argument.
pub fn panic_err<E: AsRef<[u8]>>(err: E) -> ! {
    panic_str(err_to_str(&err))
}

pub trait SdkExpect<T> {
    fn sdk_expect(self, msg: &str) -> T;
}

impl<T> SdkExpect<T> for Option<T> {
    fn sdk_expect(self, msg: &str) -> T {
        self.unwrap_or_else(|| panic_str(msg))
    }
}

impl<T, E> SdkExpect<T> for Result<T, E> {
    fn sdk_expect(self, msg: &str) -> T {
        self.unwrap_or_else(|_| panic_str(msg))
    }
}

pub trait SdkUnwrap<T> {
    fn sdk_unwrap(self) -> T;
}

impl<T> SdkUnwrap<T> for Option<T> {
    fn sdk_unwrap(self) -> T {
        self.unwrap_or_else(|| panic_str("ERR_UNWRAP"))
    }
}

impl<T, E: AsRef<[u8]>> SdkUnwrap<T> for Result<T, E> {
    fn sdk_unwrap(self) -> T {
        self.unwrap_or_else(|e| panic_str(err_to_str(&e)))
    }
}

fn err_to_str<E: AsRef<[u8]>>(err: &E) -> &str {
    from_utf8(err.as_ref()).unwrap_or(INVALID_UTF8_ERR_STRING)
}
