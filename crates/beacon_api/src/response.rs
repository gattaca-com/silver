use silver_httpcore::frame_response;

pub(crate) struct Response<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Response<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    pub(crate) fn json(&mut self, body: &[u8]) {
        frame_response(self.out, "200 OK", Some("application/json"), body);
    }

    pub(crate) fn empty(&mut self, content_type: &str) {
        frame_response(self.out, "200 OK", Some(content_type), b"");
    }

    /// Beacon-API error shape: `{"code":<status>,"message":"..."}`.
    pub(crate) fn error(&mut self, code: u16, message: &str) {
        debug_assert!(!message.contains(['"', '\\']), "message goes into JSON unescaped");
        let status = match code {
            400 => "400 Bad Request",
            405 => "405 Method Not Allowed",
            503 => "503 Service Unavailable",
            _ => unreachable!("unmapped error code {code}"),
        };
        let body = format!("{{\"code\":{code},\"message\":\"{message}\"}}");
        frame_response(self.out, status, Some("application/json"), body.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_writes_status_line_and_json_body() {
        let mut out = Vec::new();
        Response::new(&mut out).error(400, "invalid state_id");
        let expected: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"code\":400,\"message\":\"invalid state_id\"}";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_frames_ok_with_content_type() {
        let mut out = Vec::new();
        Response::new(&mut out).json(b"{\"data\":1}");
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"data\":1}"
        );
    }

    #[test]
    fn empty_frames_ok_with_zero_length_body() {
        let mut out = Vec::new();
        Response::new(&mut out).empty("text/plain");
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        );
    }
}
