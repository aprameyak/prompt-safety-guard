# Prompt Safety Guard

A multi-layer defensive system against prompt injection, jailbreaking, and other LLM prompt attacks.

## Architecture

Seven defensive layers applied sequentially:

### Layer 1: Input Validation
- Type checking and length limits
- Token count validation
- Blocked pattern detection (code injection, dangerous functions)

### Layer 2: Prompt Boundaries
- System prompt marker detection
- Jailbreak indicator detection
- Input/output delimiter enforcement

### Layer 3: Output Filtering
- Sensitive data redaction (API keys, secrets, credentials)
- Private key detection
- System prompt leakage prevention

### Layer 4: Tool Constraints
- Function whitelist validation
- Schema-based argument validation
- Dangerous operation blocking in arguments

### Layer 5: Semantic Guardrails
- Intent detection (prompt extraction attempts)
- Harmful intent identification
- Security testing detection

### Layer 6: Rate Limiting
- Per-user request tracking
- Time-windowed rate enforcement
- Behavioral anomaly detection

### Layer 7: Logging
- Comprehensive request logging
- Threat level tracking
- Rule violation reporting

## Usage

```python
from prompt_safety_guard import PromptSafetyGuard

guard = PromptSafetyGuard(log_file="safety.log")

# Guard user input
result = guard.guard_input("user_id", "user input text")
if not result.safe:
    print(f"Blocked: {result.reason}")
    print(f"Threat level: {result.threat_level.name}")

# Guard model output
output_result = guard.guard_output(model_output)
if output_result.safe:
    return output_result.sanitized_input

# Validate tool calls
tool_result = guard.validate_tool_call("function_name", {"arg": "value"})
if not tool_result.safe:
    raise PermissionError(tool_result.reason)
```

## Customization

Each layer is independent and can be configured:

```python
guard.layer1.max_length = 5000
guard.layer1.blocked_patterns.append(r"custom pattern")

guard.layer4.register_function("safe_func", {
    "required": ["arg1"],
    "properties": {"arg1": "string"}
})
```

## Testing

Run test cases:

```bash
python prompt_safety_guard.py
```

## Attack Coverage

- ✓ Prompt injection
- ✓ Jailbreaking
- ✓ Token smuggling (via input validation)
- ✓ Indirect injection (via output filtering)
- ✓ Prompt leakage
- ✓ Context confusion
- ✓ Model confusion (via tool constraints)
- ✓ Credential/secret exposure
- ✓ Rate-based attacks

## License

Apache 2.0
