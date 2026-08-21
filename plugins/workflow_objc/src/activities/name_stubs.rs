use binaryninja::{
    low_level_il::instruction::{InstructionHandler as _, LowLevelILInstructionKind},
    symbol::{Symbol, SymbolType},
    variable::PossibleValueSet,
    workflow::AnalysisContext,
};

use crate::{
    activities::objc_msg_send_calls::{call_target_type, selector_from_call, MessageSendType},
    error::ILLevel,
    metadata::GlobalState,
    Error,
};

// Reconstruct names for Objective-C selector stubs, e.g. `_objc_msgSend$length`.
// The compiler emits one of these stubs per selector. Each one does nothing but load the selector and tail-call
// `objc_msgSend`.
pub fn process(ac: &AnalysisContext) -> Result<(), Error> {
    let view = ac.view();
    if GlobalState::should_ignore_view(&view) {
        return Ok(());
    }

    let func = ac.function();
    let func_start = func.start();

    // Don't override a name the user has assigned to this function.
    if let Some(symbol) = view.symbol_by_address(func_start) {
        if !symbol.auto_defined() {
            return Ok(());
        }
    }

    // Bail out early for functions that do not look like a stub: a single basic block of a few instructions.
    const MAX_STUB_SIZE: u64 = 32;
    if func.highest_address().saturating_sub(func_start) > MAX_STUB_SIZE
        || func.basic_blocks().len() != 1
    {
        return Ok(());
    }

    let Some(llil) = (unsafe { ac.llil_function() }) else {
        return Err(Error::MissingIL {
            level: ILLevel::Low,
            func_start,
        });
    };
    let Some(ssa) = llil.ssa_form() else {
        return Err(Error::MissingSsaForm {
            level: ILLevel::Low,
            func_start,
        });
    };

    // The tail call terminates the stub's single basic block, so it can only be the last instruction.
    let blocks = ssa.basic_blocks();
    let Some(block) = blocks.iter().next() else {
        return Ok(());
    };
    let Some(insn) = block.iter().last() else {
        return Ok(());
    };
    let LowLevelILInstructionKind::TailCallSsa(call_op) = insn.kind() else {
        return Ok(());
    };

    // A selector stub does nothing besides load a selector and tail-call objc_msgSend.
    // Reject any function that performs a regular call or memory write before the tail call.
    if block.iter().any(|insn| {
        matches!(
            insn.kind(),
            LowLevelILInstructionKind::CallSsa(_)
                | LowLevelILInstructionKind::Store(_)
                | LowLevelILInstructionKind::StoreSsa(_)
        )
    }) {
        return Ok(());
    }

    let call_target = match call_op.target().possible_values() {
        PossibleValueSet::ConstantValue { value }
        | PossibleValueSet::ConstantPointerValue { value }
        | PossibleValueSet::ImportedAddressValue { value } => value as u64,
        _ => return Ok(()),
    };

    if call_target_type(&view, call_target) != Some(MessageSendType::Normal) {
        return Ok(());
    }
    let Some(selector) = selector_from_call(&view, &ssa, &call_op) else {
        return Ok(());
    };

    let name = format!("_objc_msgSend${}", selector.name);
    let symbol = Symbol::builder(SymbolType::Function, &name, func_start).create();
    view.define_auto_symbol(&symbol);

    Ok(())
}
