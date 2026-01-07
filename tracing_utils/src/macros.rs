#[macro_export]
macro_rules! function_start_log {
    () => {
        event!(
            Level::TRACE,
            type = "function_start",
            "Started.",
        )
    };
}

#[macro_export]
macro_rules! function_finish_log {
    ($result:expr $(,)?) => {
        event!(
            Level::TRACE,
            type = "function_finish",
            result = ?$result,
            "Finished.",
        )
    };
}

#[macro_export]
macro_rules! error_log {
    ($err:expr $(, $message_formatting_parts:expr )* $(,)?) => {
        event!(
            Level::WARN,
            type = "error",
            cause = ?$err,
            $($message_formatting_parts, )*
        )
    };
}

#[macro_export]
macro_rules! panic_log {
    ($err:expr $(, $message_formatting_parts:expr )* $(,)?) => {
        event!(
            Level::ERROR,
            type = "panic",
            cause = ?$err,
            $($message_formatting_parts, )*
        )
    };
}

#[macro_export]
macro_rules! traceable_unfold_or_panic {
    ($result:expr $(, $message_formatting_parts:expr )* $(,)?) => {
        $result
            .inspect_err(|err| {
                $crate::panic_log!(err, $($message_formatting_parts, )*);
            })
            .expect(format!($($message_formatting_parts, )*).as_str())
    };
}

#[macro_export]
macro_rules! traceable_unfold_or_error {
    ($result:expr $(, $message_formatting_parts:expr )* $(,)?) => {
        $result
            .inspect_err(|err| {
                $crate::error_log!(err, $($message_formatting_parts, )*);
            })?
    };
}

#[macro_export]
macro_rules! unreachable_panic {
    ($($message_formatting_part:expr),* $(,)?) => {
        $crate::panic_log!("", $($message_formatting_part, )*);
        unreachable!($($message_formatting_part, )*);
    };
}
