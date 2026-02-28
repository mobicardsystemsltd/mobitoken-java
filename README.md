# Tokenization API
## MobiToken by MobiCard
### Java

Use this multi-platform API to reduce your PCI compliance footprint by tokenizing payment card information. Store only tokens instead of actual card data, and detokenize when needed for payment processing.

With two API endpoints: Tokenization (convert card data to token) and Detokenization (convert token back to card data). Implement secure card storage while maintaining PCI DSS compliance.

Convert sensitive card data into a secure token that can be safely stored in your systems. The original card data is stored in our PCI-compliant vault.

Generate a signed JWT token with embedded request.

Send card details to receive a secure card token. Store the token and masked card number instead of actual card data.

## Success Response Format

Both methods return the same success response format when card scanning is successful.
JSON Success Response
```json
{
  "status": "SUCCESS",
  "status_code": "200",
  "status_message": "SUCCESS",
  "mobicard_txn_reference": "998470530",
  "mobicard_single_use_token_flag": "0",
  "mobicard_custom_one": "mobicard_custom_one",
  "mobicard_custom_two": "mobicard_custom_two",
  "mobicard_custom_three": "mobicard_custom_three",
  "timestamp": "2026-01-26 13:25:29",
  "card_information": {
    "card_number": "4242424242424242",
    "card_number_masked": "4242********4242",
    "card_expiry_date": "02/28",
    "card_expiry_month": "02",
    "card_expiry_year": "28",
    "card_token": "bbaefff665082af8f3a41fa51853062b1628345cec085498bba97e3ae3b1e77e4f7ac5ee0ac9bbf10ff8c151d006d80212a3dac731c48188a9e00f9084b163bf"
  },
  "addendum_data": "your_custom_data_here_will_be_returned_as_is"
}
```

## Error Response Format

Error responses have a simplified format with only 3 fields of essential information.

Use the "status" field to determine if any API request is successful or not. The value is always either "SUCCESS" or "FAILED".

```json
{
  "status": "FAILED",
  "status_code": "400",
  "status_message": "BAD REQUEST"
}
```
## Status Codes Reference

Complete list of status codes returned by the API.

| Status Code | Status | Status Message Interpretation | Action Required |
| :--- | :--- | :--- | :--- |
| **200** | `SUCCESS` | SUCCESS | Process the response data |
| **400** | `FAILED` | BAD REQUEST - Invalid parameters or malformed request | Check request parameters |
| **429** | `FAILED` | TOO MANY REQUESTS - Rate limit exceeded | Wait before making more requests |
| **250** | `FAILED` | INSUFFICIENT TOKENS - Token account balance insufficient | Top up your account |
| **500** | `FAILED` | UNAVAILABLE - Server error | Try again later or contact support |
| **430** | `FAILED` | TIMEOUT - Request timed out | Issue new token and retry |

## API Request Parameters Reference

Complete reference of all request parameters used in the Tokenization API.

| Parameter | Required | Tokenization | Detokenization | Description | Example Value |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `mobicard_version` | **Yes** | ✅ | ✅ | API version | `"2.0"` |
| `mobicard_mode` | **Yes** | ✅ | ✅ | Environment mode | `"TEST"` or `"LIVE"` |
| `mobicard_merchant_id` | **Yes** | ✅ | ✅ | Your merchant ID | `""` |
| `mobicard_api_key` | **Yes** | ✅ | ✅ | Your API key | `""` |
| `mobicard_secret_key` | **Yes** | ✅ | ✅ | Your secret key | `""` |
| `mobicard_service_id` | **Yes** | ✅ | ✅ | Service ID | `"20000"` |
| `mobicard_service_type` | **Yes** | ✅ | ✅ | Service type | `"TOKENIZATION"` |
| `mobicard_token_id` | **Yes** | ✅ | ✅ | Unique token identifier | `String/number` |
| `mobicard_txn_reference` | **Yes** | ✅ | ✅ | Your transaction reference | `String/number` |
| `mobicard_single_use_token_flag` | Tokenization | ✅ | | Single-use token flag | `"0"` or `"1"` |
| `mobicard_card_number` | Tokenization | ✅ | | Card number to tokenize | `"4242424242424242"` |
| `mobicard_card_expiry_month` | Tokenization | ✅ | | Card expiry month (MM) | `"02"` |
| `mobicard_card_expiry_year` | Tokenization | ✅ | | Card expiry year (YY) | `"28"` |
| `mobicard_card_token` | Detokenization | | ✅ | Token to detokenize | `"bbaefff6..."` |
| `mobicard_custom_one` | **No** | ✅ | | Custom data field 1 | `Any string` |
| `mobicard_custom_two` | **No** | ✅ | | Custom data field 2 | `Any string` |
| `mobicard_custom_three` | **No** | ✅ | | Custom data field 3 | `Any string` |
| `mobicard_extra_data` | **No** | ✅ | | Custom data in response | `Any string` |

## API Response Parameters Reference

Complete reference of all response parameters returned by the API.

The value for the "status" response parameter is always either "SUCCESS" or "FAILED". Use this to determine subsequent actions.

| Parameter | Always Returned | Description | Example Value |
| :--- | :---: | :--- | :--- |
| `status` | **Yes** | Transaction status | `"SUCCESS"` or `"FAILED"` |
| `status_code` | **Yes** | HTTP status code | `"200"` |
| `status_message` | **Yes** | Status description | `"SUCCESS"` |
| `mobicard_txn_reference` | **Yes** | Your original transaction reference | `"998470530"` |
| `mobicard_single_use_token_flag` | **Yes** | Single-use token flag from request | `"0"` or `"1"` |
| `timestamp` | **Yes** | Response timestamp | `"2026-01-26 13:25:29"` |
| `card_information.card_number` | **Yes** | Full card number (Detokenization only) | `"4242424242424242"` |
| `card_information.card_number_masked` | **Yes** | Masked card number (for display) | `"4242********4242"` |
| `card_information.card_expiry_date` | **Yes** | Card expiry in MM/YY format | `"02/28"` |
| `card_information.card_expiry_month` | **Yes** | Expiry month (2 digits) | `"02"` |
| `card_information.card_expiry_year` | **Yes** | Expiry year (2 digits) | `"28"` |
| `card_information.card_token` | **Yes** | Secure card token | `"bbaefff665082af8f3a41fa51853062b..."` |
| `mobicard_custom_one` | Conditional* | Custom data field 1 echoed back | `"mobicard_custom_one"` |
| `mobicard_custom_two` | Conditional* | Custom data field 2 echoed back | `"mobicard_custom_two"` |
| `mobicard_custom_three` | Conditional* | Custom data field 3 echoed back | `"mobicard_custom_three"` |
| `addendum_data` | Conditional* | Custom data echoed back from request | `"your_custom_data_here"` |


