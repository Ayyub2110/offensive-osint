# LLM Attack Advisor Implementation

## Overview

Added an LLM-powered attack advisor agent that acts as a senior red team consultant, analyzing complete reconnaissance intelligence to suggest realistic, prioritized attack paths.

## What Was Implemented

### 1. **New Agent: LLM Attack Advisor** (`agents/llm_attack_advisor_agent.py`)

**Key Features:**
- **AI-Powered Analysis**: Uses OpenAI GPT-4 (configurable) to analyze intelligence
- **Senior Red Teamer Persona**: Simulates 15+ years offensive security expertise
- **Attack Path Categories**:
  - Phishing & Social Engineering
  - Credential Attacks (stuffing, spraying, brute force)
  - JWT/Authentication Bypass
  - Account Takeover
  - Web Application Exploitation
  - API Abuse
  - Infrastructure Exploitation

**Intelligence Analysis:**
- Processes complete reconnaissance data from all agents
- Correlates findings across username, email, asset, and tech stack data
- Generates intelligence quality assessment (excellent/good/moderate/limited)

**Output Structure:**
```json
{
  "executive_summary": "High-level strategic assessment",
  "attack_paths": [
    {
      "name": "Attack path name",
      "category": "credential_attack|phishing|jwt_abuse|...",
      "description": "Detailed scenario",
      "steps": ["Step 1", "Step 2", ...],
      "prerequisites": ["Requirement 1", ...],
      "tools_required": ["Tool 1", ...],
      "success_probability": "high|medium|low",
      "detection_likelihood": "high|medium|low",
      "estimated_effort": "hours|days|weeks",
      "impact": "Expected outcome",
      "intelligence_basis": "Specific findings"
    }
  ],
  "defense_evasion_tips": ["OPSEC tip 1", ...],
  "recommended_order": ["Path 1", "Path 2", ...]
}
```

**Fallback Mode:**
- When LLM is unavailable (no API key), uses rule-based analysis
- Generates attack paths based on intelligence patterns:
  - Email patterns → Credential stuffing
  - Social media presence → Phishing campaigns
  - JWT detection → Token manipulation
  - Admin panels → Account takeover
  - No WAF → Direct web exploitation
  - Sensitive files → Configuration exploitation

### 2. **LangGraph Workflow Integration** (`graph/osint_langgraph.py`)

**Updated Workflow:**
```
START
  ↓
username_correlation
  ↓
email_inference
  ↓
asset_discovery ←──┐
  ↓                │
tech_fingerprint   │
  ↓                │
prioritization     │
  ↓                │
llm_advisor    ← NEW NODE
  ↓                │
recon_decision ────┘
  ↓
END
```

**Changes:**
- Added `llm_advisor` node after prioritization, before decision
- Updated `OSINTWorkflowState` with `attack_advisory` field
- Node processes complete intelligence and generates strategic recommendations
- Integrated into workflow execution summary

### 3. **Report Generation Updates** (`main.py`)

**Markdown Report Additions:**
- New "LLM Attack Advisory" section with:
  - Executive assessment
  - Intelligence quality rating
  - All attack paths with complete details (steps, tools, impact)
  - Recommended execution order
  - Defense evasion & OPSEC considerations

**Console Output Additions:**
- Summary of strategic attack paths (count)
- Top 3 recommended attacks with success probability

## Configuration

### Environment Variables (.env)

```bash
# Required for LLM-powered analysis
OPENAI_API_KEY=your_api_key_here

# Optional - Model selection
LLM_MODEL=gpt-4                    # or gpt-4-turbo, gpt-3.5-turbo
LLM_TEMPERATURE=0.7                # 0.0-1.0 (creativity vs consistency)
```

### Without LLM (Fallback Mode)

The agent works without API keys using rule-based analysis:
- Still generates attack paths
- Based on deterministic intelligence patterns
- Less nuanced but functional
- No API costs

## Usage Examples

### Basic Usage (Automatic)

```bash
# LLM advisor runs automatically in the workflow
python main.py --domain targetcorp.com

# Output includes:
# - Asset discovery
# - Tech fingerprinting
# - Prioritization
# - LLM Attack Advisory ← NEW
# - Markdown report with attack paths
```

### Example Output

**Console:**
```
[LLM ADVISOR] Generating strategic attack recommendations...
[LLM ADVISOR] Generated 5 strategic attack path recommendations
[LLM ADVISOR] Top recommendation: Credential Stuffing Campaign
[LLM ADVISOR] Success probability: HIGH

⚔️  Strategic Attack Paths: 5 recommended
   1. Credential Stuffing Campaign
      Category: credential_attack | Success Probability: HIGH
   2. Targeted Phishing via Social Media Intelligence
      Category: phishing | Success Probability: HIGH
   3. JWT Token Manipulation Attack
      Category: jwt_abuse | Success Probability: MEDIUM
```

**Markdown Report Section:**
```markdown
## LLM Attack Advisory

*Strategic attack path recommendations from AI-powered red team advisor*

### Executive Assessment

Analysis identified 5 viable attack paths. 2 paths have HIGH success probability. 
Recommended initial approach: Credential Stuffing Campaign. 
Intelligence quality: excellent.

**Intelligence Quality:** Excellent
**Analysis Model:** gpt-4

### Recommended Attack Paths (5 identified)

#### 1. Credential Stuffing Campaign
**Category:** credential_attack | **Success:** HIGH | **Detection Risk:** MEDIUM | **Effort:** days

**Description:** Leverage 15 validated email patterns for credential stuffing...

**Execution Steps:**
1. Collect email:password pairs from breach databases
2. Test 15 email patterns against authentication endpoints
3. Use rotating proxies to avoid rate limiting
...

**Tools Required:** CredMaster, Snipr, Burp Suite Intruder, Rotating Proxy Service

**Expected Impact:** Account compromise enabling lateral movement...

*Intelligence Basis: Generated 15 validated email patterns with domain confirmation*
```

## Attack Path Examples

### 1. Credential Stuffing
**When Generated:** Email patterns validated + authentication endpoints found
**Intelligence Basis:** Validated emails + MX records
**Tools:** CredMaster, Snipr, Burp Suite
**Success:** Medium-High

### 2. Phishing Campaign
**When Generated:** Username found on social platforms
**Intelligence Basis:** GitHub, Twitter, Reddit profiles
**Tools:** Gophish, Evilginx2, SET
**Success:** High

### 3. JWT Manipulation
**When Generated:** JWT/Bearer auth detected
**Intelligence Basis:** Tech stack fingerprinting
**Tools:** jwt_tool, Burp JWT Editor, Hashcat
**Success:** Medium

### 4. Account Takeover
**When Generated:** Admin/login panels discovered
**Intelligence Basis:** High-priority admin endpoints
**Tools:** Burp Suite, Custom scripts
**Success:** Medium

### 5. Direct Web Exploitation
**When Generated:** No WAF detected
**Intelligence Basis:** Missing security controls
**Tools:** sqlmap, Burp Suite Pro, Nuclei
**Success:** High (if vulnerable)

## Security & Legal Considerations

**Important:**
- Advisory output is for **authorized testing only**
- Does NOT include actual exploits or malicious payloads
- Acts as strategic guidance, not auto-exploitation
- User responsible for legal compliance

**LLM Prompt Safety:**
- System prompt enforces advisory-only output
- Explicitly instructs against including exploit code
- Focuses on methodology, not weaponization

## Architecture Design Decisions

### Why After Prioritization?
- Needs complete intelligence picture
- Uses prioritized targets for context
- Generates attack paths based on highest-value targets

### Why Before Decision Node?
- Attack advisory doesn't affect recon loop
- Decision based on asset coverage, not attack paths
- Advisory is final intelligence synthesis

### Why LLM vs Pure Rules?
- **LLM Benefits:**
  - Contextual correlation across intelligence sources
  - Natural language strategic guidance
  - Adapts to unique target profiles
  - Simulates senior expert reasoning

- **Rule-Based Fallback:**
  - Works without API costs
  - Deterministic and debuggable
  - Covers common attack patterns
  - No dependency on external services

## Future Enhancements

### Potential Improvements:
1. **Multi-LLM Support**: Claude, Llama, local models
2. **Custom Personas**: Junior vs senior red teamer modes
3. **Attack Chain Building**: Multi-stage attack planning
4. **Success Prediction**: ML-based success probability
5. **CVE Integration**: Map tech stack to known vulnerabilities
6. **Historical Learning**: Learn from past engagement outcomes
7. **Team Collaboration**: Multi-agent red team simulation

## Testing

### Verify LLM Mode:
```bash
# Set API key
export OPENAI_API_KEY="your_key"

# Run workflow
python main.py --domain example.com

# Check output for:
# [LLM ADVISOR] Using OpenAI GPT-4
# "model_used": "gpt-4" in JSON output
```

### Verify Fallback Mode:
```bash
# Unset API key
unset OPENAI_API_KEY

# Run workflow
python main.py --domain example.com

# Check output for:
# [LLM ADVISOR] LLM not configured - using rule-based analysis
# "model_used": "rule-based (LLM not available)"
```

## Performance

**LLM Mode:**
- Additional 5-15 seconds per workflow execution
- Cost: ~$0.01-0.05 per analysis (GPT-4)
- Token usage: ~2000-4000 tokens

**Fallback Mode:**
- Near-instant (< 1 second)
- Zero API costs
- No external dependencies

## Summary

The LLM Attack Advisor transforms raw reconnaissance data into actionable offensive security guidance, acting as a virtual senior red team consultant. It provides:

✅ **Strategic recommendations** based on complete intelligence  
✅ **Prioritized attack paths** with success probabilities  
✅ **Step-by-step execution guidance** for each approach  
✅ **OPSEC considerations** for stealth operations  
✅ **Fallback mode** for offline/cost-free operation  
✅ **Professional reporting** in Markdown and JSON  

This positions the framework as a comprehensive pre-attack intelligence and planning platform for offensive security professionals.
