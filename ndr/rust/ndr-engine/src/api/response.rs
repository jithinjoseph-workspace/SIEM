// NDR Engine — Standard API Response Envelope
// Every endpoint should return Json<ApiResponse<T>> for consistency.

use axum::Json;
use serde::Serialize;
use serde_json::Value;

#[allow(dead_code)]
#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub result: bool,
    pub data:   Option<T>,
    pub error:  Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<ApiResponse<T>> {
        Json(ApiResponse { result: true, data: Some(data), error: None })
    }

    pub fn err(message: impl Into<String>) -> Json<ApiResponse<T>> {
        Json(ApiResponse { result: false, data: None, error: Some(message.into()) })
    }
}

#[allow(dead_code)]
pub type JsonResponse = Json<ApiResponse<Value>>;

#[allow(dead_code)]
pub fn ok(data: Value) -> JsonResponse {
    ApiResponse::ok(data)
}

#[allow(dead_code)]
pub fn err_response(message: impl Into<String>) -> JsonResponse {
    ApiResponse::<Value>::err(message)
}
