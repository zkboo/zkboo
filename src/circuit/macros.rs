// SPDX-License-Identifier: LGPL-3.0-or-later

//! Macros for ZKBoo circuits.
//! 🚧 Work in Progress 🚧

#[macro_export]
#[doc(hidden)]
macro_rules! _def_circuit_struct {
    ($name: ident, {
            $($fields:tt)*
        }
    ) => {
        $crate::circuit::macros::def_circuit_struct!(@parse
            struct $name {}
            $($fields)*
        );
    };

    (@parse
        struct $name:ident { $($out:tt)* }
    ) => {
        #[derive(Debug)]
        struct $name { $($out)* }
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ],
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::def_circuit_struct!(@parse
            struct $name {
                $($out)*
                $field: [$crate::word::CompositeWord<$w, $n>; $m],
            }
            $($rest)*
        );
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : [ $w:ty ; $n:expr ],
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::def_circuit_struct!(@parse
            struct $name {
                $($out)*
                $field: $crate::word::CompositeWord<$w, $n>,
            }
            $($rest)*
        );
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : $w:ty,
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::def_circuit_struct!(@parse
            struct $name {
                $($out)*
                $field: $w,
            }
            $($rest)*
        );
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ]
    ) => {
        #[derive(Debug)]
        struct $name {
            $($out)*
            $field: [CompositeWord<$w, $n>; $m],
        }
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : [ $w:ty ; $n:expr ]
    ) => {
        #[derive(Debug)]
        struct $name {
            $($out)*
            $field: $crate::word::CompositeWord<$w, $n>,
        }
    };

    (@parse
        struct $name:ident { $($out:tt)* }
        $field:ident : $w:ty
    ) => {
        #[derive(Debug)]
        struct $name {
            $($out)*
            $field: $w,
        }
    };
}

pub use _def_circuit_struct as def_circuit_struct;

#[macro_export]
#[doc(hidden)]
macro_rules! _impl_circuit_constructor {
    ($name:ident, {
        $($fields:tt)*
    }) => {
        $crate::circuit::macros::impl_circuit_constructor!(@parse
            impl $name { () () }
            $($fields)*
        );
    };

    (@parse
        impl $name:ident {
            ($($params:tt)*)
            ($($inits:tt)*)
        }
    ) => {
        impl $name {
            pub fn new($($params)*) -> Self {
                Self {
                    $($inits)*
                }
            }
        }
    };

    // [[W; N]; M]
    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ],
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::impl_circuit_constructor!(@parse
            impl $name {
                ($($p)* $field: [[ $w ; $n ]; $m],)
                ($($i)* $field: $field.map(|x| $crate::word::CompositeWord::from_le_words(x)),)
            }
            $($rest)*
        );
    };

    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ]
    ) => {
        impl $name {
            pub fn new($($p)* $field: [[ $w ; $n ]; $m],) -> Self {
                Self {
                    $($i)*
                    $field: $field.map(|x| $crate::word::CompositeWord::from_le_words(x)),
                }
            }
        }
    };

    // [W;N]
    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : [ $w:ty ; $n:expr ],
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::impl_circuit_constructor!(@parse
            impl $name {
                ($($p)* $field: [ $w ; $n ],)
                ($($i)* $field: $crate::word::CompositeWord::from_le_words($field),)
            }
            $($rest)*
        );
    };

    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : [ $w:ty ; $n:expr ]
    ) => {
        impl $name {
            pub fn new($($p)* $field: [ $w ; $n ],) -> Self {
                Self {
                    $($i)*
                    $field: $crate::word::CompositeWord::from_le_words($field),
                }
            }
        }
    };

    // W
    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : $w:ty,
        $($rest:tt)*
    ) => {
        $crate::circuit::macros::impl_circuit_constructor!(@parse
            impl $name {
                ($($p)* $field: $w,)
                ($($i)* $field: $field,)
            }
            $($rest)*
        );
    };

    (@parse
        impl $name:ident { ($($p:tt)*) ($($i:tt)*) }
        $field:ident : $w:ty
    ) => {
        impl $name {
            pub fn new($($p)* $field: $w,) -> Self {
                Self {
                    $($i)*
                    $field: $field,
                }
            }
        }
    };
}

pub use _impl_circuit_constructor as impl_circuit_constructor;

#[macro_export]
#[doc(hidden)]
macro_rules! _impl_circuit_exec {
    ($name:ident, $fun:expr,
    { frontend, $($in_name:ident : $in_ty:tt),* $(,)? },
    { $($out_name:ident : $out_ty:tt),* $(,)? }
    ) => {
        impl $crate::circuit::Circuit for $name {
            fn exec<B: $crate::backend::Backend, F: $crate::backend::Frontend<B>>(&self, frontend: &mut F) {
                $crate::circuit::macros::impl_circuit_exec!(@inputs frontend self;
                    $($in_name : $in_ty),*
                );

                $crate::circuit::macros::impl_circuit_exec!(@output_declarations;
                    $($out_name : $out_ty),*
                );

                ($($out_name),*) =
                    $fun(frontend, $($in_name),*);

                $crate::circuit::macros::impl_circuit_exec!(@outputs frontend;
                    $($out_name : $out_ty),*
                );
            }
        }
    };

    ($name:ident, $fun:expr,
    { $($in_name:ident : $in_ty:tt),* $(,)? },
    { $($out_name:ident : $out_ty:tt),* $(,)? }
    ) => {
        impl $crate::circuit::Circuit for $name {
            fn exec<B: $crate::backend::Backend, F: $crate::backend::Frontend<B>>(&self, frontend: &mut F) {
                $crate::circuit::macros::impl_circuit_exec!(@inputs frontend self;
                    $($in_name : $in_ty),*
                );

                $crate::circuit::macros::impl_circuit_exec!(@output_declarations;
                    $($out_name : $out_ty),*
                );

                ($($out_name),*) =
                    $fun($($in_name),*);

                $crate::circuit::macros::impl_circuit_exec!(@outputs frontend;
                    $($out_name : $out_ty),*
                );
            }
        }
    };

    // ---------------- function args ----------------

    // expand directly into comma-separated expressions

    (@expand_args) => {};

    (@expand_args $field:ident : $ty:ty, $($rest:tt)*) => {
        $field, $crate::circuit::macros::impl_circuit_exec!(@expand_args $($rest)*)
    };

    (@expand_args $field:ident : $ty:ty) => {
        $field
    };
    // ---------------- output names ----------------

    (@out_names $field:ident : $ty:ty, $($rest:tt)*) => {
        $field, $crate::circuit::macros::impl_circuit_exec!(@out_names $($rest)*)
    };

    (@out_names $field:ident : $ty:ty) => {
        $field
    };

    // ---------------- inputs ----------------

    (@inputs $fe:ident $slf:ident;) => {};

    (@inputs $fe:ident $slf:ident;
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ],
        $($rest:tt)*
    ) => {
        // struct field type is: [CompositeWord<$w,$n>; $m]
        let $field: [$crate::backend::WordRef<B, $w, $n>; $m] = $slf.$field.map(|cw| $fe.input(cw));
        $crate::circuit::macros::impl_circuit_exec!(@inputs $fe $slf; $($rest)*);
    };

    (@inputs $fe:ident $slf:ident;
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ]
    ) => {
        let $field: [$crate::backend::WordRef<B, $w, $n>; $m] = $slf.$field.map(|cw| $fe.input(cw));
    };

    // [W; N]
    (@inputs $fe:ident $slf:ident;
        $field:ident : [ $w:ty ; $n:expr ],
        $($rest:tt)*
    ) => {
        // struct field type is: CompositeWord<$w,$n>
        let $field: $crate::backend::WordRef<B, $w, $n> = $fe.input($slf.$field);
        $crate::circuit::macros::impl_circuit_exec!(@inputs $fe $slf; $($rest)*);
    };

    (@inputs $fe:ident $slf:ident;
        $field:ident : [ $w:ty ; $n:expr ]
    ) => {
        let $field: WordRef<B, $w, $n> = $fe.input($slf.$field);
    };

    // W
    (@inputs $fe:ident $slf:ident;
        $field:ident : $w:ty,
        $($rest:tt)*
    ) => {
        let $field: $crate::backend::WordRef<B, $w> =
            $fe.input($crate::word::CompositeWord::<$w, 1>::from_le_words([$slf.$field]));
        $crate::circuit::macros::impl_circuit_exec!(@inputs $fe $slf; $($rest)*);
    };

    (@inputs $fe:ident $slf:ident;
        $field:ident : $w:ty
    ) => {
        let $field: WordRef<B, $w> =
            $fe.input($crate::word::CompositeWord::<$w, 1>::from_le_words([$slf.$field]));
    };

    // ---------------- output declarations ----------------

    (@output_declarations;) => {};

    (@output_declarations;
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ],
        $($rest:tt)*
    ) => {
        // struct field type is: [CompositeWord<$w,$n>; $m]
        let $field: [$crate::backend::WordRef<B, $w, $n>; $m];
        $crate::circuit::macros::impl_circuit_exec!(@output_declarations; $($rest)*);
    };

    (@output_declarations;
        $field:ident : [[ $w:ty ; $n:expr ] ; $m:expr ]
    ) => {
        let $field: [$crate::backend::WordRef<B, $w, $n>; $m];
    };

    // [W; N]
    (@output_declarations;
        $field:ident : [ $w:ty ; $n:expr ],
        $($rest:tt)*
    ) => {
        // struct field type is: CompositeWord<$w,$n>
        let $field: $crate::backend::WordRef<B, $w, $n>;
        $crate::circuit::macros::impl_circuit_exec!(@output_declarations; $($rest)*);
    };

    (@output_declarations;
        $field:ident : [ $w:ty ; $n:expr ]
    ) => {
        let $field: $crate::backend::WordRef<B, $w, $n>;
    };

    // W
    (@output_declarations;
        $field:ident : $w:ty,
        $($rest:tt)*
    ) => {
        let $field: $crate::backend::WordRef<B, $w>;
        $crate::circuit::macros::impl_circuit_exec!(@output_declarations; $($rest)*);
    };

    (@output_declarations;
        $field:ident : $w:ty
    ) => {
        let $field: $crate::backend::WordRef<B, $w>;
    };

    // ---------------- outputs ----------------

    (@outputs $fe:ident;) => {};

    (@outputs $fe:ident;
        $field:ident : $ty:ty,
        $($rest:tt)*
    ) => {
        $fe.output($field);
        $crate::circuit::macros::impl_circuit_exec!(@outputs $fe; $($rest)*);
    };

    (@outputs $fe:ident;
        $field:ident : $ty:ty
    ) => {
        $fe.output($field);
    };
}

pub use _impl_circuit_exec as impl_circuit_exec;

#[macro_export]
#[doc(hidden)]
macro_rules! _circuit {
    ($name:ident, $fun:expr, { frontend, $($inputs:tt)* }, { $($outputs:tt)* }) => {
        $crate::circuit::macros::def_circuit_struct!($name, { $($inputs)* });
        $crate::circuit::macros::impl_circuit_constructor!($name, { $($inputs)* });
        $crate::circuit::macros::impl_circuit_exec!($name, $fun, { frontend, $($inputs)* }, { $($outputs)* });
    };
    ($name:ident, $fun:expr, { $($inputs:tt)* }, { $($outputs:tt)* }) => {
        $crate::circuit::macros::def_circuit_struct!($name, { $($inputs)* });
        $crate::circuit::macros::impl_circuit_constructor!($name, { $($inputs)* });
        $crate::circuit::macros::impl_circuit_exec!($name, $fun, { $($inputs)* }, { $($outputs)* });
    };
}

pub use _circuit as circuit;

// TODO: Document the circuit macro (use the example + one with frontend argument).

// use zkboo::circuit::{Circuit, circuit};

// fn foo<B: Backend>(
//     a: zkboo::backend::WordRef<B, u32>,
//     b: zkboo::backend::WordRef<B, u8, 4>,
//     d: [zkboo::backend::WordRef<B, u8, 4>; 8],
// ) -> (
//     zkboo::backend::WordRef<B, u32>,
//     zkboo::backend::WordRef<B, u32, 4>,
// ) {
//     unimplemented!()
// }

// circuit!(Test, foo, {
//     a: u32,
//     b: [u8; 4],
//     d: [[u8; 4]; 8],
// }, {
//     x: u32,
//     y: [u32; 4]
// });

// fn bar<B: Backend, F: Frontend<B>>(mut frontend: F) {
//     let test = Test::new(1u32, [1u8; 4], [[1u8; 4]; 8]);
//     test.exec(&mut frontend);
//     circuit!(Baz, |a, b|{a & b}, {
//         inl: u32,
//         inr: u32,
//     }, {
//         outl: u32,
//     });
// }
