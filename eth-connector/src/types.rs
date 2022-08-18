use near_sdk::env::panic_str;

#[macro_export]
macro_rules! log {
    ($e: expr) => {
        #[cfg(feature = "log")]
        near_sdk::log!($e)
    };
}

pub trait SdkExpect<T> {
    fn sdk_expect(self, msg: &str) -> T;
}

impl<T> SdkExpect<T> for Option<T> {
    fn sdk_expect(self, msg: &str) -> T {
        match self {
            Some(t) => t,
            None => panic_str(msg),
        }
    }
}

impl<T, E> SdkExpect<T> for core::result::Result<T, E> {
    fn sdk_expect(self, msg: &str) -> T {
        match self {
            Ok(t) => t,
            Err(_) => panic_str(msg),
        }
    }
}

pub trait SdkUnwrap<T> {
    fn sdk_unwrap(self) -> T;
}

impl<T> SdkUnwrap<T> for Option<T> {
    fn sdk_unwrap(self) -> T {
        match self {
            Some(t) => t,
            None => panic_str("ERR_UNWRAP"),
        }
    }
}

impl<T, E: AsRef<[u8]>> SdkUnwrap<T> for core::result::Result<T, E> {
    fn sdk_unwrap(self) -> T {
        match self {
            Ok(t) => t,
            Err(e) => panic_str(&String::from_utf8(e.as_ref().to_vec()).unwrap()),
        }
    }
}
