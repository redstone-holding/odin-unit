package unit

import "core:c"
import "core:fmt"
import "core:mem"
import "core:log"
import "core:strings"
import "core:runtime"

when ODIN_OS == .Windows {
	foreign import unit_lib "system:unit.lib";
} else {
	foreign import unit_lib "system:unit";
}

@(default_calling_convention="c")
foreign unit_lib {
	nxt_unit_init							:: proc(unit_init: ^Unit_Init) -> ^Unit_Ctx ---
	nxt_unit_run							:: proc(ctx: ^Unit_Ctx) -> Unit_Code ---
	nxt_unit_run_ctx						:: proc(ctx: ^Unit_Ctx) -> Unit_Code ---
	nxt_unit_run_shared						:: proc(ctx: ^Unit_Ctx) -> Unit_Code ---
	nxt_unit_dequeue_request				:: proc(ctx: ^Unit_Ctx) -> ^Unit_Request_Info ---
	nxt_unit_run_once						:: proc(ctx: ^Unit_Ctx) -> c.int ---
	nxt_unit_process_port_msg				:: proc(ctx: ^Unit_Ctx, port: Unit_Port) -> c.int ---
	nxt_unit_done							:: proc(ctx: ^Unit_Ctx) ---
	nxt_unit_ctx_alloc						:: proc(ctx: ^Unit_Ctx, data: rawptr) -> ^Unit_Ctx ---
	nxt_unit_port_id_init					:: proc(port_id: ^Unit_Port_Id, pid: c.int, id: c.uint16_t) ---
	nxt_unit_field_hash						:: proc(name: cstring, name_length: c.size_t) -> c.uint16_t ---
	nxt_unit_split_host						:: proc(host_start: cstring, host_length: c.uint32_t, name: ^cstring, name_length: ^c.uint32_t, port: ^cstring, port_length: ^c.uint32_t) ---
	nxt_unit_request_group_dup_fields		:: proc(req: ^Unit_Request_Info) ---
	nxt_unit_response_init					:: proc(req: ^Unit_Request_Info, status: c.uint16_t, max_fields_count: c.uint32_t, max_fields_size: c.uint32_t) -> Unit_Code ---
	nxt_unit_response_realloc				:: proc(req: ^Unit_Request_Info, max_fields_count: c.uint32_t, max_fields_size: c.uint32_t) -> Unit_Code ---
	nxt_unit_response_is_init				:: proc(req: ^Unit_Request_Info) -> Unit_Code ---
	nxt_unit_response_add_field				:: proc(req: ^Unit_Request_Info, name: cstring, name_length: c.uint8_t, value: cstring, value_length: c.uint32_t) -> Unit_Code ---
	nxt_unit_response_add_content			:: proc(req: ^Unit_Request_Info, src: rawptr, size: c.uint32_t) -> Unit_Code ---
	nxt_unit_response_send					:: proc(req: ^Unit_Request_Info) -> c.int ---
	nxt_unit_response_is_sent				:: proc(req: ^Unit_Request_Info) -> c.int ---
	nxt_unit_response_buf_alloc				:: proc(req: ^Unit_Request_Info, size: c.uint32_t) -> ^Unit_Buf ---
	nxt_unit_request_is_websocket_handshake	:: proc(req: ^Unit_Request_Info) -> c.int ---
	nxt_unit_response_upgrade				:: proc(req: ^Unit_Request_Info) -> c.int ---
	nxt_unit_response_is_websocket			:: proc(req: ^Unit_Request_Info) -> c.int ---
	nxt_unit_get_request_info_from_data		:: proc(data: rawptr) -> ^Unit_Request_Info ---
	nxt_unit_buf_send						:: proc(buf: ^Unit_Buf) -> c.int ---
	nxt_unit_buf_free						:: proc(buf: ^Unit_Buf) ---
	nxt_unit_buf_next						:: proc(buf: ^Unit_Buf) -> ^Unit_Buf ---
	nxt_unit_buf_max						:: proc() -> c.uint32_t ---
	nxt_unit_buf_min						:: proc() -> c.uint32_t ---
	nxt_unit_response_write					:: proc(req: ^Unit_Request_Info, start: rawptr, size: c.size_t) -> c.int ---
	nxt_unit_response_write_nb				:: proc(req: ^Unit_Request_Info, start: rawptr, size: c.size_t, min_size: c.size_t) -> c.ssize_t ---
	nxt_unit_response_write_cb				:: proc(req: ^Unit_Request_Info, read_info: ^Unit_Read_Info) -> c.int ---
	nxt_unit_request_read					:: proc(req: ^Unit_Request_Info, read_info: rawptr, size: c.size_t) -> c.ssize_t ---
	nxt_unit_request_readline_size			:: proc(req: ^Unit_Request_Info, max_size: c.size_t) -> c.ssize_t ---
	nxt_unit_request_done					:: proc(req: ^Unit_Request_Info, rc: c.int) ---
	nxt_unit_websocket_send					:: proc(req: ^Unit_Request_Info, opcode: c.uint8_t, last: c.uint8_t, start: rawptr, size: c.size_t) -> c.int ---
	nxt_unit_websocket_sendv				:: proc(req: ^Unit_Request_Info, opcode: c.uint8_t, last: c.uint8_t, iov: IO_Vec, iovcnt: c.int ) -> c.int ---
	nxt_unit_websocket_read					:: proc(ws: ^Unit_Web_Socket_Frame, read_info: rawptr, size: c.size_t) -> c.ssize_t ---
	nxt_unit_websocket_retain				:: proc(ws: ^Unit_Web_Socket_Frame) -> c.int ---
	nxt_unit_websocket_done					:: proc(ws: ^Unit_Web_Socket_Frame) ---
	nxt_unit_malloc							:: proc(ctx: ^Unit_Ctx, size: c.size_t) -> rawptr ---
	nxt_unit_free							:: proc(ctx: ^Unit_Ctx, p: rawptr) ---
	nxt_unit_log							:: proc(ctx: ^Unit_Ctx, level: Unit_Log_Level, fmt: cstring, args: ..any) ---
	nxt_unit_req_log						:: proc(req: ^Unit_Request_Info, level: Unit_Log_Level, fmt: cstring, args: ..any) ---
}


// https://man7.org/linux/man-pages/man2/readv.2.html
//
IO_Vec :: struct {
	iov_base:	rawptr,    // Starting address
	iov_len:	c.size_t,  // Number of bytes to transfer
};


Unit_Code :: enum c.int {
    NXT_UNIT_OK          = c.int(0),
    NXT_UNIT_ERROR       = 1,
    NXT_UNIT_AGAIN       = 2,
    NXT_UNIT_CANCELLED   = 3,
};


Unit_Log_Level :: enum c.int {
    NXT_UNIT_LOG_ALERT   = 0,
    NXT_UNIT_LOG_ERR     = 1,
    NXT_UNIT_LOG_WARN    = 2,
    NXT_UNIT_LOG_NOTICE  = 3,
    NXT_UNIT_LOG_INFO    = 4,
    NXT_UNIT_LOG_DEBUG   = 5,
}


// Mostly opaque structure with library state.
//
// Only user defined 'data' pointer exposed here.  The rest is unit implementation specific and hidden.
//
// https://github.com/nginx/unit/blob/9ff59e6c4bc09b0252810b709bd5f6aa35f76691/src/nxt_unit.h#L40-L48
//
Unit :: struct {
	data:  rawptr  // User defined data
}


// Thread context.
//
// First (main) context is provided 'for free'.  To receive and process
// requests in other thread, one needs to allocate a context and use it
// further in that thread.
// 
// https://github.com/nginx/unit/blob/9ff59e6c4bc09b0252810b709bd5f6aa35f76691/src/nxt_unit.h#L50-L60
//
Unit_Ctx :: struct {
	data:	rawptr,  // User context-specific data.
	unit:	^Unit,
}


// ...
// https://github.com/nginx/unit/blob/9ff59e6c4bc09b0252810b709bd5f6aa35f76691/src/nxt_unit_request.h#L17-L50
//
Unit_Request :: struct {
	method_length:			c.uint8_t,
	version_length:			c.uint8_t,
	remote_length:			c.uint8_t,
	local_addr_length:		c.uint8_t,
	local_port_length:		c.uint8_t,
	tls:					c.uint8_t,
	websocket_handshake:	c.uint8_t,
	app_target:				c.uint8_t,
	server_name_length:		c.uint32_t,
	target_length:			c.uint32_t,
	path_length:			c.uint32_t,
	query_length:			c.uint32_t,
	fields_count:			c.uint32_t,
	content_length_field:	c.uint32_t,
	content_type_field:		c.uint32_t,
	cookie_field:			c.uint32_t,
	authorization_field:	c.uint32_t,
	content_length:			c.uint64_t,
	method:					Unit_Sptr,
	version:				Unit_Sptr,
	remote:					Unit_Sptr,
	local_addr:				Unit_Sptr,
	local_port:				Unit_Sptr,
	server_name:			Unit_Sptr,
	target:					Unit_Sptr,
	path:					Unit_Sptr,
	query:					Unit_Sptr,
	preread_content:		Unit_Sptr,
	fields: 				[]Unit_Field,
}


// ...
// https://unit.nginx.org/
Unit_Response :: struct {
}


// Name and Value field aka HTTP header
// https://github.com/nginx/unit/blob/b42f6b1dc8186effaeac566518700e80b2415a41/src/nxt_unit_field.h#L21-L31
//
Unit_Field :: struct {
	hash:			c.uint16_t,
	skip:			c.uint8_t, // :1
	hopbyhop:		c.uint8_t, // :1
	name_length:	c.uint8_t,
	value_length:	c.uint32_t,
	name:			Unit_Sptr,
	value:			Unit_Sptr,
}


// ...
// https://unit.nginx.org/
//
Unit_Web_Socket_Frame :: struct {
}


// Unit port identification structure.
//
// Each port can be uniquely identified by listen process id (pid) and port id.
// This identification is required to refer the port from different process.
//
// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L62-L72
//
Unit_Port_Id :: struct {
	pid:	c.int,
	hash:	c.uint32_t,
	id:		c.uint16_t,
}


// Unit provides port storage which is able to store and find the following
// data structures.
//
// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L74-L85
//
Unit_Port :: struct {
	id:			Unit_Port_Id,
    in_fd:		c.int,
    out_fd:		c.int,
    data:		rawptr,
}


// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L88-L92
//
Unit_Buf :: struct {
	start:	^u8,
    free:	^u8,
    end:	^u8,	
}


// https://github.com/nginx/unit/blob/9ff59e6c4bc09b0252810b709bd5f6aa35f76691/src/nxt_unit.h#L95-L113
//
Unit_Request_Info :: struct {
	unit:					^Unit,
	ctx:					^Unit_Ctx,
	response_port:			^Unit_Port,
	request:				^Unit_Request,
	request_buf:			^Unit_Buf,
	response:				^Unit_Response,
	response_buf:			^Unit_Buf,
	response_max_fields:	c.uint32_t,
	content_buf:			^Unit_Buf,
	content_length:			c.uint64_t,
	content_fd:				c.int,
	data:					rawptr,
}


// Set of application-specific callbacks. Application may leave all callbacks as nil,
// except {request_handler}.
//
// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L120-L161
//
Unit_Callbacks :: struct {
	request_handler:	proc "c" (req: ^Unit_Request_Info),						// Process request
	data_handler:		proc "c" (req: ^Unit_Request_Info),						// Data received
	websocket_handler:	proc "c" (wsf: ^Unit_Web_Socket_Frame),					// Process websocket frame
	close_handler:		proc "c" (req: ^Unit_Request_Info),						// Connection closed
	add_port:			proc "c" (ctx: ^Unit_Ctx, port: Unit_Port) -> c.int,	// Add new Unit port to communicate with process pid
	remove_port:		proc "c" (uni: ^Unit, ctx: ^Unit_Ctx, port: Unit_Port),	// Remove previously added port
	remove_pid:			proc "c" (uni: ^Unit, pid: Unit_Pid),					// Remove all data associated with process pid including ports
	quit:				proc "c" (ctx: ^Unit_Ctx),								// Gracefully quit the application
	shm_ack_handler:	proc "c" (ctx: ^Unit_Ctx),								// Shared memory release acknowledgement
	port_send:			proc "c" (ctx: ^Unit_Ctx, port: Unit_Port, buf: rawptr, buf_size: c.size_t, oob: rawptr, oob_size: c.size_t) -> c.size_t, // Send data and control to process pid using port id
	port_recv:			proc "c" (ctx: ^Unit_Ctx, port: Unit_Port, buf: rawptr, buf_size: c.size_t, oob: rawptr, oob_size: c.size_t) -> c.size_t, // Receive data on port id
	ready_handler:		proc "c" (ctx: ^Unit_Ctx) -> c.int,
}


// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L164-L182
//
Unit_Init :: struct {
	data:					rawptr,
	ctx_data:				rawptr,
	max_pending_requests:	c.int,
	request_data_size:		c.uint32_t,
	shm_limit:				c.uint32_t,
	request_limit:			c.uint32_t,
	callbacks:				Unit_Callbacks,
	ready_port:				Unit_Port,
	ready_stream:			c.uint32_t,
	router_port:			Unit_Port,
	read_port:				Unit_Port,
	shared_port_fd:			c.int,
	shared_queue_fd:		c.int,
	log_fd:					c.int,
}


// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L185-L186
//
Unit_Read_Func :: proc "c" (read_info: ^Unit_Read_Info, dst: rawptr, size: c.size_t) -> c.ssize_t


// https://github.com/nginx/unit/blob/master/src/nxt_unit.h#L189-L194
//
Unit_Read_Info :: struct {
	read:		Unit_Read_Func,
	eof:		c.int,
	buf_size:	c.uint32_t,
	data:		rawptr,
};


// ...
// https://unit.nginx.org/
//
Unit_Pid :: struct {
}


// Serialized pointer
// https://github.com/nginx/unit/blob/9ff59e6c4bc09b0252810b709bd5f6aa35f76691/src/nxt_unit_sptr.h#L17-L21
//
Unit_Sptr :: struct #raw_union {
    base: 		u8,
    offset:		c.uint32_t,
}


unit_sptr_set :: #force_inline proc(sptr: ^Unit_Sptr, ptr: rawptr) {
	sptr.offset = (u32)(mem.ptr_sub((^u8)(ptr), &sptr.base)) // TODO: Investigate
}

unit_sptr_get :: #force_inline proc(sptr: ^Unit_Sptr) -> ^u8 {
	return mem.ptr_offset(&sptr.base, sptr.offset)
}


unit_debug :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_DEBUG, fmt, ..args)
}

unit_info :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_INFO, fmt, ..args)
}

unit_notice :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_NOTICE, fmt, ..args)
}

unit_warn :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_WARN, fmt, ..args)
}

unit_alert :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_ALERT, fmt, ..args)
}

unit_err :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_ERR, fmt, ..args)
}


unit_req_debug :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_DEBUG, fmt, args)
}

unit_req_info :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_INFO, fmt, args)
}

unit_req_notice :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_NOTICE, fmt, args)
}

unit_req_warn :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_WARN, fmt, args)
}

unit_req_err :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_ERR, fmt, args)
}

unit_req_alert :: #force_inline proc(ctx: ^Unit_Ctx, fmt: cstring, args: ..any) {
	nxt_unit_log(ctx, .NXT_UNIT_LOG_ALERT, fmt, args)
}



request_handler :: proc "c" (req: ^Unit_Request_Info) {
	context = runtime.default_context()

	fmt.println("request_handler")

	target: cstring = (cstring)(unit_sptr_get(&req.request.target));

	// TODO: Make wrapper
	if rc := nxt_unit_response_init(req, 101, 0, 0); rc != .NXT_UNIT_OK {

	}

/*
    int rc = NXT_UNIT_OK;
    char * target = nxt_unit_sptr_get(&req->request->target);

    if (strcmp(target, "/") == 0) {
        if (!nxt_unit_request_is_websocket_handshake(req)) {
            goto notfound;
        }

        rc = nxt_unit_response_init(req, 101, 0, 0);

        if (rc != NXT_UNIT_OK) {
            goto fail;
        }

        nxt_unit_response_upgrade(req);
        nxt_unit_response_send(req);

        return;
    }

notfound:
    rc = nxt_unit_response_init(req, 404, 0, 0);

fail:
    nxt_unit_request_done(req, rc);
*/
}


websocket_handler :: proc "c" (ws: ^Unit_Web_Socket_Frame) {

}


main :: proc() {
	context.logger = log.create_console_logger(); // TODO: Use NGINX Unit logger

	init : Unit_Init = {
		callbacks = {
			request_handler = request_handler,
			websocket_handler = websocket_handler,
		},
		// ctx_data = cast(rawptr) context,
	}

	// TODO Make #force_inline wrapper
	ctx := nxt_unit_init(&init)
}
