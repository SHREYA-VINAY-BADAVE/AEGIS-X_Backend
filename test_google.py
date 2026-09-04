import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestGoogleAuth")

def test_endpoint():
    logger.info("Verifying Google OAuth Endpoint...")
    
    # Test 1: Sending empty payload
    try:
        response = requests.post("http://127.0.0.1:8000/api/auth/google", json={})
        logger.info(f"Test Empty Payload Response Code: {response.status_code}")
        assert response.status_code == 422, "Expected validation error (422)"
    except Exception as e:
        logger.error(f"Failed to connect to backend server: {e}")
        return False

    # Test 2: Sending invalid token
    response = requests.post("http://127.0.0.1:8000/api/auth/google", json={"credential": "dummy_google_jwt_token_format_12345"})
    logger.info(f"Test Dummy Token Response Code: {response.status_code}")
    logger.info(f"Test Dummy Token Response Body: {response.text}")
    
    assert response.status_code == 401, "Expected 401 Unauthorized for invalid Google token"
    assert "Invalid Google credential token" in response.text or "Failed to verify Google token" in response.text
    
    logger.info("Google login backend endpoint verification SUCCESS!")
    return True

if __name__ == "__main__":
    success = test_endpoint()
    if not success:
        exit(1)
