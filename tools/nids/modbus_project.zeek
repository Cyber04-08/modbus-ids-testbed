##! This project's rule-based detector (detectors/rule_based.py) as a Zeek
##! script, including the replay check that Suricata rules cannot express.
##!
##! Writes one line per alerting request to modbus_project.log:
##!   ts, client port, transaction ID, function code, rule name.
##!
##! Register map: HR0 = tank level (sensor, read-only), HR1 = pump setpoint
##! (%), coil 0 = inlet valve, coil 1 = outlet valve. Allowed function codes:
##! 1, 3, 5, 6, 16.
##!
##! Usage: zeek -C -r run_01.pcap modbus_project.zeek

module ModbusProject;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:    time   &log;
        port_: count  &log;
        tid:   count  &log;
        fc:    count  &log;
        rule:  string &log;
    };
}

const allowed_fc: set[count] = { 1, 3, 5, 6, 16 };
const write_fc: set[count] = { 5, 6, 15, 16 };

# Per connection: transaction ID -> what that request wrote. Used by the
# replay rule: a write reusing an ID already seen with the same content.
global seen_writes: table[conn_id] of table[count] of string &create_expire=1hr;

event zeek_init()
    {
    Log::create_stream(ModbusProject::LOG, [$columns=Info, $path="modbus_project"]);
    }

function alert(c: connection, h: ModbusHeaders, rule: string)
    {
    Log::write(ModbusProject::LOG, [$ts=network_time(), $port_=port_to_count(c$id$orig_p),
                                    $tid=h$tid, $fc=h$function_code, $rule=rule]);
    }

# Replay rule shared by every write handler. Returns T if it fired.
function check_replay(c: connection, h: ModbusHeaders, content: string): bool
    {
    if ( c$id !in seen_writes )
        seen_writes[c$id] = table();
    local seen = seen_writes[c$id];
    if ( h$tid in seen && seen[h$tid] == content )
        {
        alert(c, h, "replay_reused_txid");
        return T;
        }
    seen[h$tid] = content;
    return F;
    }

# Rule 1: function code not in the plant's allowed set (requests only).
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    {
    if ( is_orig && headers$function_code !in allowed_fc )
        alert(c, headers, "function_code_not_allowed");
    }

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count)
    {
    if ( address != 1 )
        alert(c, headers, "write_to_readonly_address");
    else if ( value > 100 )
        alert(c, headers, "value_out_of_range");
    else
        check_replay(c, headers, fmt("6/%d/%d", address, value));
    }

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                              start_address: count,
                                              registers: ModbusRegisters)
    {
    local n = |registers|;
    if ( start_address != 1 || n > 1 )
        alert(c, headers, "write_to_readonly_address");
    else if ( registers[0] > 100 )
        alert(c, headers, "value_out_of_range");
    else
        check_replay(c, headers, fmt("16/%d/%s", start_address, registers));
    }

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                       address: count, value: bool)
    {
    if ( address > 1 )
        alert(c, headers, "write_to_readonly_address");
    else
        check_replay(c, headers, fmt("5/%d/%s", address, value));
    }
