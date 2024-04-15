#[macro_export]
macro_rules! or_else {
	($e:expr, $($else:tt)+) => {
		if let Some(v) = $e {
			v
		} else {
			return $($else)+;
		}
	};
}
