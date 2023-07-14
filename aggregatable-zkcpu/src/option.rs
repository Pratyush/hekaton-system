use std::borrow::Borrow;

use ark_ff::Field;
use ark_r1cs_std::{
    convert::ToBitsGadget,
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::word::WordVar;

#[must_use]
pub struct OptionVar<T, F: Field> {
    is_some: Boolean<F>,
    value: Option<T>,
}

impl<T, F: Field> OptionVar<T, F> {
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self {
        is_some: Boolean::FALSE,
        value: None,
    };

    #[allow(non_snake_case)]
    pub fn Some(val: T) -> Self {
        Self {
            is_some: Boolean::TRUE,
            value: Some(val),
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Querying the contained values
    /////////////////////////////////////////////////////////////////////////

    /// Returns `true` if the option is a `Some` value.
    #[must_use = "if you intended to assert that this has a value, consider `.unwrap()` instead"]
    #[inline]
    pub fn is_some(&self) -> Boolean<F> {
        self.is_some.clone()
    }

    /// Returns `true` if the option is a [`None`] value.
    #[must_use = "if you intended to assert that this doesn't have a value, consider \
                  `.and_then(|_| panic!(\"`Option` had a value when expected `None`\"))` instead"]
    #[inline]
    pub fn is_none(&self) -> Boolean<F> {
        !self.is_some()
    }

    /////////////////////////////////////////////////////////////////////////
    // Getting to contained values
    /////////////////////////////////////////////////////////////////////////

    /// Returns the contained `Some` value, consuming the `self` value.
    ///
    /// # Panics
    ///
    /// Panics if the value is a `None` with a custom panic message provided by
    /// `msg`.
    #[inline]
    #[track_caller]
    pub fn expect(self, msg: &str) -> Result<T, SynthesisError> {
        self.is_some.enforce_equal(&Boolean::TRUE)?;
        Ok(self.value.expect(msg))
    }

    /// Returns the contained [`Some`] value, consuming the `self` value.
    #[inline]
    #[track_caller]
    pub fn unwrap(self, msg: &str) -> Result<T, SynthesisError> {
        self.expect("called `Option::unwrap()` on a `None` value")
    }

    /// Returns the contained [`Some`] value or a provided default.
    ///
    /// Arguments passed to `unwrap_or` are eagerly evaluated; if you are passing
    /// the result of a function call, it is recommended to use [`unwrap_or_else`],
    /// which is lazily evaluated.
    #[inline]
    pub fn unwrap_or(self, default: T) -> Result<T, SynthesisError> {
        self.is_some.select(&self.value.unwrap(), &default)
    }

    /// Returns the contained [`Some`] value or a default.
    ///
    /// Consumes the `self` argument then, if [`Some`], returns the contained
    /// value, otherwise if [`None`], returns the [default value] for that
    /// type.
    ///
    /// # Examples
    ///
    /// ```
    /// let x: Option<u32> = None;
    /// let y: Option<u32> = Some(12);
    ///
    /// assert_eq!(x.unwrap_or_default(), 0);
    /// assert_eq!(y.unwrap_or_default(), 12);
    /// ```
    ///
    /// [default value]: Default::default
    /// [`parse`]: str::parse
    /// [`FromStr`]: crate::str::FromStr
    #[inline]
    pub fn unwrap_or_default(self) -> Result<T, SynthesisError>
    where
        T: Default,
    {
        self.unwrap_or(T::default())
    }

    /////////////////////////////////////////////////////////////////////////
    // Transforming contained values
    /////////////////////////////////////////////////////////////////////////

    /// Maps an `Option<T>` to `Option<U>` by applying a function to a contained value (if `Some`) or returns `None` (if `None`).
    #[inline]
    pub const fn map<U>(self, f: impl FnOnce(T) -> U) -> Result<OptionVar<U, F>, SynthesisError> {
        let u = self.value.map(f);
        Self {
            is_some: self.is_some,
            value: u,
        }
    }

    /// Returns the provided default result (if none),
    /// or applies a function to the contained value (if any).
    ///
    /// Arguments passed to `map_or` are eagerly evaluated.
    #[inline]
    pub const fn map_or<U>(self, default: U, f: impl FnOnce(T) -> U) -> Result<U, SynthesisError> {
        let u = self.value.map_or(default, f);
        self.is_some.select(&u, &default)
    }

    /////////////////////////////////////////////////////////////////////////
    // Boolean operations on the values, eager and lazy
    /////////////////////////////////////////////////////////////////////////

    /// Returns [`None`] if the option is [`None`], otherwise returns `optb`.
    ///
    /// Arguments passed to `and` are eagerly evaluated; if you are passing the
    /// result of a function call, it is recommended to use [`and_then`], which is
    /// lazily evaluated.
    ///
    /// [`and_then`]: Option::and_then
    #[inline]
    pub fn and<U>(self, optb: OptionVar<U, F>) -> Result<OptionVar<U, F>, SynthesisError> {
        let u = self.value.and(optb.value);
        Ok(Self {
            is_some: self.is_some & optb.is_some,
            value: u,
        })
    }

    /// Returns the option if it contains a value, otherwise returns `optb`.
    ///
    /// Arguments passed to `or` are eagerly evaluated.
    #[inline]
    pub fn or(self, optb: Self) -> Result<Self, SynthesisError> {
        let u = self.value.or(optb.value);
        Ok(Self {
            is_some: self.is_some | optb.is_some,
            value: u,
        })
    }

    /// Returns [`Some`] if exactly one of `self`, `optb` is [`Some`], otherwise returns [`None`].
    #[inline]
    pub fn xor(self, optb: Self) -> Result<Self, SynthesisError> {
        let u = self.value.xor(optb.value);
        Ok(Self {
            is_some: self.is_some ^ optb.is_some,
            value: u,
        })
    }

    /////////////////////////////////////////////////////////////////////////
    // Entry-like operations to insert a value and return a reference
    /////////////////////////////////////////////////////////////////////////

    /// Inserts `value` into the option, then returns a mutable reference to it.
    ///
    /// If the option already contains a value, the old value is dropped.
    ///
    /// See also [`Option::get_or_insert`], which doesn't update the value if
    /// the option already contains [`Some`].
    #[must_use = "if you intended to set a value, consider assignment instead"]
    #[inline]
    pub fn insert(&mut self, value: T) -> Result<&mut T, SynthesisError> {
        self.is_some = Boolean::TRUE;
        Ok(self.value.insert(value))
    }

    /// Inserts `value` into the option if it is [`None`], then
    /// returns a mutable reference to the contained value.
    ///
    /// See also [`Option::insert`], which updates the value even if
    /// the option already contains [`Some`].
    #[inline]
    pub const fn get_or_insert(&mut self, value: T) -> Result<&mut T, SynthesisError> {
        self.is_some = Boolean::TRUE;
        Ok(self.value.get_or_insert(value))
    }

    /// Inserts the default value into the option if it is [`None`], then
    /// returns a mutable reference to the contained value.
    #[inline]
    pub fn get_or_insert_default(&mut self) -> Result<&mut T, SynthesisError>
    where
        T: Default,
    {
        self.get_or_insert(T::default())
    }

    /////////////////////////////////////////////////////////////////////////
    // Misc
    /////////////////////////////////////////////////////////////////////////

    /// Takes the value out of the option, leaving a [`None`] in its place.
    #[inline]
    pub fn take(&mut self) -> Result<Self, SynthesisError> {
        let result = self.clone();
        self.is_some = Boolean::FALSE;
        Ok(result)
    }

    /// Replaces the actual value in the option by the value given in parameter,
    /// returning the old value if present,
    /// leaving a [`Some`] in its place without deinitializing either one.
    #[inline]
    pub fn replace(&mut self, value: T) -> Result<Self, SynthesisError> {
        let result = self.clone();
        *self = Self::Some(value);
        result
    }

    /// Zips `self` with another `Option`.
    ///
    /// If `self` is `Some(s)` and `other` is `Some(o)`, this method returns `Some((s, o))`.
    /// Otherwise, `None` is returned.
    pub fn zip<U>(self, other: OptionVar<U, F>) -> Result<OptionVar<(T, U), F>, SynthesisError> {
        let value = self.value.zip(other.value);
        let is_some = self.is_some & other.is_some;
        Ok(Self { is_some, value })
    }
}

impl<T, U, F: Field> OptionVar<(T, U), F> {
    /// Unzips an option containing a tuple of two options.
    ///
    /// If `self` is `Some((a, b))` this method returns `(Some(a), Some(b))`.
    /// Otherwise, `(None, None)` is returned.
    ///
    #[inline]
    pub fn unzip(self) -> Result<(OptionVar<T, F>, OptionVar<U, F>), SynthesisError> {
        let (value_t, value_u) = self.value.unzip();
        let is_some_t = self.is_some.clone();
        let is_some_u = self.is_some;
        let t = OptionVar {
            is_some: is_some_t,
            value: value_t,
        };
        let u = OptionVar {
            is_some: is_some_u,
            value: value_u,
        };
        Ok((t, u))
    }
}

impl<T, F> OptionVar<&T, F> {
    /// Maps an `Option<&T>` to an `Option<T>` by copying the contents of the
    /// option.
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn copied(self) -> OptionVar<T, F>
    where
        T: Copy,
    {
        self.map(|&t| t)
    }

    /// Maps an `Option<&T>` to an `Option<T>` by cloning the contents of the
    /// option.
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn cloned(self) -> Option<T>
    where
        T: Clone,
    {
        self.map(|&t| t.clone())
    }
}

impl<T, F: Field> OptionVar<&mut T, F> {
    /// Maps an `Option<&mut T>` to an `Option<T>` by copying the contents of the
    /// option.
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn copied(self) -> OptionVar<T, F>
    where
        T: Copy,
    {
        match self {
            Some(&mut t) => Some(t),
            None => None,
        }
    }

    /// Maps an `Option<&T>` to an `Option<T>` by cloning the contents of the
    /// option.
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn cloned(self) -> Option<T>
    where
        T: Clone,
    {
        self.map(|t| t.clone())
    }
}

impl<T, F: Field> Default for OptionVar<T, F> {
    /// Returns [`None`].
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

impl<T, F: Field> From<T> for OptionVar<T, F> {
    /// Moves `val` into a new [`Some`].
    fn from(val: T) -> Self {
        Self::Some(val)
    }
}

impl<T: EqGadget<F>, F: Field> EqGadget<F> for OptionVar<T, F> {
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let is_some = self.is_some.is_eq(&other.is_some)?;
        let value = self.value.is_eq(&other.value)?;
        Ok(is_some & value)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        self.is_some
            .conditional_enforce_equal(&other.is_some, should_enforce)?;
        self.value
            .conditional_enforce_equal(&other.value, should_enforce)?;
        Ok(())
    }
}

impl<T: R1CSVar<F>, F: Field> R1CSVar<F> for OptionVar<T, F> {
    type Value = Option<T::Value>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.is_some
            .cs()
            .or(self.value.map_or(ConstraintSystemRef::None, |v| v.cs()))
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self.is_some.value()? {
            true => {
                assert!(self.value.is_some());
                self.value.unwrap().value()
            },
            false => Ok(None),
        }
    }
}

impl<G: Clone, T: AllocVar<G, F>, F: Field> AllocVar<Option<G>, F> for OptionVar<T, F> {
    fn new_variable<S: Borrow<Option<G>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<S, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        f().and_then(|s| match s.borrow() {
            Some(g) => T::new_variable(ns, || Ok(g.clone()), mode).map(Self::Some),
            None => Ok(Self::None),
        })
    }
}

impl<'a, T: WordVar<F>, F: Field> ToBitsGadget<F> for &'a OptionVar<T, F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let is_some = self.is_some();
        match self.value {
            Some(val) => Ok([vec![is_some], self.value.unwrap().as_le_bits()].concat()),
            None => Ok([vec![is_some], T::zero().as_le_bits()].concat()),
        }
    }
}

impl<T: WordVar<F>, F: Field> ToBitsGadget<F> for OptionVar<T, F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        <&Self>::to_bits_le(&self)
    }
}

impl<T, F: Field> Default for OptionVar<T, F> {
    fn default() -> Self {
        OptionVar::None
    }
}

impl<T: WordVar<F>, F: Field> OptionVar<T, F> {
    /// Create a `OptionVar` from a bitstring. Panics if `bits.len() != WV::BITLEN + 1`.
    pub(crate) fn from_bits_le(bits: &[Boolean<F>]) -> Self {
        assert_eq!(bits.len(), T::BIT_LENGTH + 1);
        let (is_some, value) = bits.split_first().unwrap();
        let is_some = is_some.clone();
        let value = Some(T::from_le_bits(value));

        Self { is_some, value }
    }
}
