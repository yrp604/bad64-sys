use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase as _, BinaryViewExt},
    confidence::Conf,
    function::Function,
    low_level_il::{
        function::{Mutable, SSA},
        instruction::LowLevelILInstruction,
    },
    rc::Ref,
    types::{FunctionParameter, Type},
};

use super::MessageSendType;
use crate::{metadata::Selector, workflow::Confidence, Error};

fn named_type(bv: &BinaryView, name: &str) -> Option<Ref<Type>> {
    bv.type_by_name(name)
        .map(|t| Type::named_type_from_type(name, &t))
}

pub fn process_call(
    bv: &BinaryView,
    func: &Function,
    insn: &LowLevelILInstruction<Mutable, SSA>,
    selector: &Selector,
    message_send_type: MessageSendType,
) -> Result<(), Error> {
    let arch = func.arch();
    let id = named_type(bv, "id").unwrap_or_else(|| Type::pointer(&arch, &Type::void()));
    let (receiver_type, receiver_name) = match message_send_type {
        MessageSendType::Normal => (id.clone(), "self"),
        MessageSendType::Super => (
            Type::pointer(
                &arch,
                &named_type(bv, "objc_super").unwrap_or_else(Type::void),
            ),
            "super",
        ),
    };
    let sel = named_type(bv, "SEL").unwrap_or_else(|| Type::pointer(&arch, &Type::char()));

    // TODO: Infer return type based on receiver type / selector.
    let return_type = id.clone();

    let mut params = vec![
        FunctionParameter::new(receiver_type, receiver_name.to_string(), None),
        FunctionParameter::new(sel, "sel".to_string(), None),
    ];

    let argument_labels = selector.argument_labels();
    let mut argument_names = generate_argument_names(&argument_labels);

    // Pad out argument names if necessary
    for i in argument_names.len()..argument_labels.len() {
        argument_names.push(format!("arg{i}"));
    }

    // Create types for all arguments. For now they're all signed integers of the platform word size.
    let arg_type = Type::int(bv.address_size(), true);
    params.extend(
        argument_names
            .into_iter()
            .map(|name| FunctionParameter::new(arg_type.clone(), name, None)),
    );

    let func_type = Type::function(&return_type, params, false);
    func.set_auto_call_type_adjustment(
        insn.address(),
        Conf::new(func_type, Confidence::ObjCMsgSend as u8).as_ref(),
        Some(arch),
    );

    Ok(())
}

fn selector_label_without_prefix(prefix: &str, label: &str) -> Option<String> {
    if label.len() <= prefix.len() || !label.starts_with(prefix) {
        return None;
    }

    let after_prefix = &label[prefix.len()..];

    // If the character after the prefix is lowercase, the label may be something like "settings"
    // in which case "set" should not be considered a prefix.
    let (first, rest) = after_prefix.split_at_checked(1)?;
    if first.chars().next()?.is_lowercase() {
        return None;
    }

    // Lowercase the first character if the second character is not also uppercase.
    // This ensures we leave initialisms such as `URL` alone.
    let (second, rest) = rest.split_at_checked(1)?;
    Some(match second.chars().next() {
        Some(c) if c.is_lowercase() => {
            format!("{}{}{}", first.to_lowercase(), second, rest)
        }
        _ => after_prefix.to_string(),
    })
}

fn argument_name_from_selector_label(label: &str) -> String {
    // TODO: Handle other common patterns such as <do some action>With<arg>: and <do some action>For<arg>:
    let prefixes = [
        "initWith", "with", "and", "using", "set", "read", "to", "for",
    ];

    for prefix in prefixes {
        if let Some(arg_name) = selector_label_without_prefix(prefix, label) {
            return arg_name;
        }
    }

    label.to_owned()
}

fn generate_argument_names(labels: &[String]) -> Vec<String> {
    labels
        .iter()
        .map(|label| argument_name_from_selector_label(label))
        .collect()
}
