// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use smallvec::smallvec;
use std::collections::VecDeque;
use sui_types::attestation::attestation_verify_inner;
pub fn aws_attestation_verify(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 2);

    // todo: figure out cost

    let attestation = pop_arg!(args, VectorRef);
    let user_data = pop_arg!(args, VectorRef);

    let attestation_ref = attestation.as_bytes_ref();
    let user_data_ref = user_data.as_bytes_ref();

    if attestation_verify_inner(&attestation_ref, &user_data_ref).is_err() {
        Ok(NativeResult::ok(
            InternalGas::zero(),
            smallvec![Value::bool(false)],
        ))
    } else {
        Ok(NativeResult::ok(
            InternalGas::zero(),
            smallvec![Value::bool(true)],
        ))
    }
}
