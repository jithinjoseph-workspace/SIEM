//! Wazuh's configuration error/warning texts (`error_messages.h`,
//! `warning_messages.h`), so logs read exactly like a Wazuh manager's.

pub fn xml_error(file: &str, err: &str, line: u32) -> String {
    format!("(1226): Error reading XML file '{file}': {err} (line {line}).")
}
pub fn xml_invelem(el: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{el}'.")
}
pub const XML_ELEMNULL: &str = "(1231): Invalid NULL element in the configuration.";
pub fn xml_invattr(attr: &str, where_: &str) -> String {
    format!("(1233): Invalid attribute '{attr}' in the configuration: '{where_}'.")
}
pub fn xml_valuenull(el: &str) -> String {
    format!("(1234): Invalid NULL content for element: {el}.")
}
pub fn xml_valueerr(el: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{el}': {v}.")
}
pub fn invalid_ip(ip: &str) -> String {
    format!("(1237): Invalid ip address: '{ip}'.")
}
pub const CONN_ERROR: &str = "(1201): No remote connection configured.";
pub fn config_error(file: &str) -> String {
    format!("(1202): Configuration error at '{file}'.")
}
pub fn port_error(p: i64) -> String {
    format!("(1205): Invalid port number: '{p}'.")
}
pub const DUP_SECURE: &str = "(1244): Can't add more than one secure connection.";
pub fn regex_compile(re: &str, err: i32) -> String {
    format!("(1450): Syntax error on regex: '{re}': {err}.")
}
pub fn def_not_found(high: &str, low: &str) -> String {
    format!("(2301): Definition not found for: '{high}.{low}'.")
}
pub fn inv_def(high: &str, low: &str, v: &str) -> String {
    format!("(2302): Invalid definition for {high}.{low}: '{v}'.")
}
pub fn fgets_error(file: &str, line: &str) -> String {
    format!("(1119): Invalid line on file '{file}': {line}.")
}
pub fn remoted_net_protocol_error(default: &str) -> String {
    format!("(9000): Error getting protocol. Default value ({default}) will be used.")
}
pub fn remoted_inv_value_ignore(v: &str, opt: &str) -> String {
    format!("(9001): Ignored invalid value '{v}' for '{opt}'.")
}
pub fn remoted_net_protocol_only_secure(default: &str) -> String {
    format!("(9002): Only secure connection supports TCP and UDP at the same time. Default value ({default}) will be used.")
}
pub fn remoted_inv_value_default(v: &str, opt: &str) -> String {
    format!("(9004): Invalid value '{v}' in '{opt}' option. Default value will be used.")
}
