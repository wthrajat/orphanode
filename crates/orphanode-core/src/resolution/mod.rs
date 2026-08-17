//! Module resolution boundary.

mod module_resolver;

pub use module_resolver::{
    ModuleResolution, ModuleResolver, OxcModuleResolver, ResolutionFailure, is_relative,
};
