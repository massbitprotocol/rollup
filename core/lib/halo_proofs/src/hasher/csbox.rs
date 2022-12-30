use crate::hasher::bn256::{PowerSBox, QuinticSBox, SBox};
use crate::hasher::rescue_hasher::RescueEngine;

pub trait CsSBox<E: RescueEngine>: SBox<E> {}

impl<E: RescueEngine> CsSBox<E> for QuinticSBox<E> {}

impl<E: RescueEngine> CsSBox<E> for PowerSBox<E> {}
