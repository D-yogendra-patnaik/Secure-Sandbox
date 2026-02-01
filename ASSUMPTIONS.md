# Assumptions and Design Decisions

## Python Version
- Minimum Python version: 3.11
- All code tested with Python 3.11+ features and type hints

## Docker Availability
- Docker is optional but required for dynamic analysis
- System gracefully degrades when Docker is not available
- API continues to work with static analysis and ML even without Docker

## Semgrep Installation
- Semgrep may not be installed by default
- System returns warning if semgrep is unavailable
- Static analysis is skipped gracefully without semgrep

## File Size Limits
- Maximum upload size: 10MB
- Prevents resource exhaustion attacks
- Reasonable limit for most malware samples

## Sandbox Security
- Docker containers run with no network access (--network none)
- Memory limited to 256MB per container
- CPU limited to 0.5 cores
- Execution timeout of 10 seconds
- Only Python and text files executed in sandbox
- Binary files (.exe, .dll) rejected for safety

## ML Model
- Synthetic training data generated if dataset missing
- Model auto-trains on first API use if not present
- Simple Random Forest classifier for demonstration
- Real deployment would require real malware samples

## Feature Engineering
- Features designed to be explainable and deterministic
- Entropy calculation uses Shannon entropy
- String counting uses minimum length of 4 characters
- Import counting specific to Python files

## API Design
- RESTful API with FastAPI
- File upload via multipart/form-data
- URL-based analysis via JSON POST body
- Comprehensive JSON response with all analysis results

## Error Handling
- Graceful degradation when tools unavailable
- Clear error messages in warnings array
- HTTP 400 for client errors, 500 for server errors
- No sensitive information leaked in error messages

## Testing
- Tests designed to pass even without Docker
- Tests check for proper error handling
- Sample files included for reproducibility
- CI workflow builds but doesn't require Docker to pass

## Concurrency
- FastAPI handles concurrent requests naturally
- Each request gets isolated temporary files
- Proper cleanup of resources after analysis

## Production Considerations
- This is a proof-of-concept/educational tool
- NOT recommended for public deployment without security review
- Would need authentication, rate limiting, and additional hardening
- Malware samples should be handled in isolated environments