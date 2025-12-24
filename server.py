# server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import re
import math
import secrets
from collections import Counter
from fastapi.middleware.cors import CORSMiddleware

# ---------------- CONFIG / THRESHOLDS ----------------
MAX_GUESSES = 10**14               # hard cap for displayed guess counts
WORDLIKE_GUES_CAP = 10**9          # conservative cap for human-word-like passwords
STRONG_SUGGESTION_GUESSES = 10**12 # only accept suggestions >= this when possible
SUGGESTION_ATTEMPTS = 60           # attempts to produce strong suggestions

app = FastAPI(title="NextGen Password Checker - Final")

# enable CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DATA (small demo lists; expand in prod) ----------------
COMMON = {
    "password", "123456", "qwerty", "abc123", "letmein",
    "111111", "123123", "admin", "welcome"
}

COMMON_WORD_RANK = {
    "the": 1, "be": 2, "to": 3, "of": 4, "and": 5, "a": 6,
    "orbit": 1200, "silent": 8000, "rocket": 4000, "correct": 1500,
    "horse": 2000, "battery": 3000, "staple": 5000, "sunset": 9000,
    "maple": 11000, "luna": 15000, "pixel": 20000, "quasar": 25000,
    "nebula": 30000, "aurora": 32000, "cipher": 45000
}
DEFAULT_RANK = 50000

WORDS = ["maple", "sunset", "orbit", "pixel", "river", "coffee", "vault", "rocket", "silent", "matrix", "paper", "tango", "luna"]
RARE_WORDS = ["luna", "quasar", "nebula", "zephyr", "odyssey", "aurora", "cipher", "quantum", "voyager"]
SYMBOLS = "!@#$%&*?-_=+"

# ---------------- BASIC HELPERS ----------------
def has_upper(p): return any(c.isupper() for c in p)
def has_lower(p): return any(c.islower() for c in p)
def has_digit(p): return any(c.isdigit() for c in p)
def has_symbol(p): return any(not c.isalnum() for c in p)

def shannon_entropy_bits(pw: str) -> float:
    if not pw:
        return 0.0
    counts = Counter(pw)
    L = len(pw)
    ent = -sum((c / L) * math.log2(c / L) for c in counts.values())
    return ent * L

def keyboard_pattern(pw: str) -> bool:
    s = pw.lower()
    if "password" in s:
        return True
    for seq in ["qwerty", "asdf", "zxcv", "1234", "4321"]:
        if seq in s:
            return True
    if re.search(r"0123|1234|2345|3456|4567|5678|6789", s):
        return True
    return False

def date_like(pw: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", pw))

# ---------------- WORD-LIKE DETECTION (robust, not over-aggressive) ----------------
def looks_word_like(pw: str) -> bool:
    """Return True if password is human-word-like (multi-word, camelcase, mostly alpha, pronounceable long chunk)."""
    if not pw or len(pw) < 4:
        return False

    pw_low = pw.lower()

    # 1) Two or more alphabetic chunks of length >=3
    blocks = re.findall(r"[A-Za-z]{3,}", pw)
    if len(blocks) >= 2:
        return True

    # 2) CamelCase two-segment pattern (WordWord)
    if re.search(r"(?:[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,})", pw):
        return True

    # 3) Mostly alphabetic characters (threshold lowered to avoid false positives on short strings)
    letters = sum(c.isalpha() for c in pw)
    if len(pw) > 0 and (letters / len(pw)) > 0.7 and len(pw) >= 8:
        # require length >=8 to avoid flagging short human+symbol examples
        return True

    # 4) Pronounceable vowel-consonant-vowel patterns but only if they form a fairly long chunk
    vowel_chunks = re.findall(r"[aeiou]{1,2}[bcdfghjklmnpqrstvwxyz]{1,3}[aeiou]", pw_low)
    if len("".join(vowel_chunks)) >= 6:
        return True

    # 5) Multiple capitalized name-like pieces (e.g., "JohnDoeSmith")
    name_chunks = re.findall(r"[A-Z][a-z]{2,8}", pw)
    if len(name_chunks) >= 2:
        return True

    # 6) Common mutated "password"-like leet patterns
    if re.search(r"[p@][a4][s5][s5w][o0][r4][d|d]", pw_low):
        return True

    return False

# ---------------- WORD SPLITTING ----------------
def split_into_words(token: str) -> List[str]:
    # CamelCase split
    if re.search(r"[A-Z][a-z]+", token):
        parts = re.findall(r"[A-Z][a-z]*", token)
        if len(parts) > 1:
            return [p.lower() for p in parts]
    # fallback: split on non-alpha
    cleaned = re.sub(r"[^A-Za-z]", " ", token)
    parts = [p.lower() for p in cleaned.split() if p]
    if parts:
        return parts
    return [token.lower()]

# ---------------- GUESS ESTIMATORS ----------------
def word_combo_guess_count(pw: str) -> float:
    core = re.sub(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "", pw)
    words = split_into_words(core)
    if len(words) == 1:
        return 0.0

    guesses = 1.0
    for w in words:
        guesses *= COMMON_WORD_RANK.get(w, DEFAULT_RANK)

    # capitalization multiplier
    if re.search(r"[A-Z]", core):
        guesses *= 2.0 if re.fullmatch(r"(?:[A-Z][a-z]+)+", core) else 5.0

    # suffix multipliers
    if re.search(r"[^A-Za-z0-9]+$", pw):
        guesses *= 20.0
    if re.search(r"\d+$", pw):
        guesses *= 50.0

    return float(min(guesses, MAX_GUESSES))

def estimate_guesses_improved(pw: str) -> float:
    wc = word_combo_guess_count(pw)
    if wc and wc > 0:
        return wc
    ent = shannon_entropy_bits(pw)
    return float(min(2 ** min(ent, 60), MAX_GUESSES))

def pretty_time_to_crack(guesses: float, guesses_per_second: float = 1e7) -> str:
    seconds = float(guesses) / float(guesses_per_second)
    units = [
        ("years", 60*60*24*365),
        ("days", 60*60*24),
        ("hours", 60*60),
        ("minutes", 60),
        ("seconds", 1)
    ]
    for name, sec in units:
        if seconds >= sec:
            return f"{seconds/sec:.1f} {name}"
    return "under 1 second"

# ---------------- SCORING HELPERS ----------------
def clamp(v: float, a: int = 0, b: int = 100) -> int:
    return max(a, min(b, int(round(v))))

def clamp_score_from_guesses(guesses: float) -> int:
    if guesses <= 1:
        return 0
    val = math.log2(guesses + 2)
    mapped = (val - 10) / 30 * 100
    return clamp(mapped, 0, 100)

def score_label(score: int) -> str:
    if score < 25: return "Weak"
    if score < 50: return "Fair"
    if score < 75: return "Good"
    if score < 90: return "Strong"
    return "Excellent"

# ---------------- CORE ANALYSIS ----------------
def score_and_explain(pw: str, leaked: bool = False) -> Dict:
    reasons: List[str] = []

    if not pw:
        return {"score": 0, "label": "Weak", "reasons": ["empty"], "entropy_bits": 0.0,
                "guesses_estimate": 0, "ttc": "under 1 second"}

    if pw.lower() in COMMON:
        return {"score": 0, "label": "Weak", "reasons": ["common password"], "entropy_bits": 0.0,
                "guesses_estimate": 0, "ttc": "under 1 second"}

    # WORD-LIKE: early conservative handling
    if looks_word_like(pw):
        reasons.append("password contains human-like word structures (readable / multi-word / name-like).")
        reasons.append("These patterns are attacked using pattern/dictionary/PCFG models and are much faster to guess than raw entropy.")
        raw_guess = estimate_guesses_improved(pw)
        # conservative cap for readable structures so UI reflects reality
        guesses_int = int(min(max(1, round(raw_guess)), WORDLIKE_GUES_CAP))
        ttc = pretty_time_to_crack(guesses_int)
        return {
            "score": 0,
            "label": "Weak",
            "reasons": reasons,
            "entropy_bits": round(shannon_entropy_bits(pw), 2),
            "guesses_estimate": guesses_int,
            "ttc": ttc
        }

    length = len(pw)
    variety = sum([has_lower(pw), has_upper(pw), has_digit(pw), has_symbol(pw)])
    ent = shannon_entropy_bits(pw)

    length_score = min(length * 3, 45)
    variety_score = (variety / 4) * 30
    entropy_score = min(ent / 40 * 25, 25)

    penalty = 0
    if keyboard_pattern(pw):
        penalty += 12; reasons.append("keyboard pattern detected")
    if re.search(r"(.)\1\1", pw):
        penalty += 8; reasons.append("repeated character sequence")
    if date_like(pw):
        penalty += 6; reasons.append("date-like substring")
    if len(set(pw)) <= max(2, length // 4):
        penalty += 6; reasons.append("low character diversity")

    raw = clamp(length_score + variety_score + entropy_score - penalty, 0, 100)
    if leaked:
        raw = min(raw, 10)
        reasons.insert(0, "found in public breach (leaked)")

    label = score_label(int(round(raw)))

    guesses = estimate_guesses_improved(pw)
    # enforce caps and integer response
    guesses_int = int(min(max(1, round(guesses)), MAX_GUESSES))
    ttc = pretty_time_to_crack(guesses_int)

    if length < 12:
        reasons.append("prefer 12+ characters")
    if variety < 3:
        reasons.append("add uppercase/digits/symbols")
    if ent < 28:
        reasons.append("low entropy")

    return {
        "score": int(round(raw)),
        "label": label,
        "reasons": reasons,
        "entropy_bits": round(ent, 2),
        "guesses_estimate": guesses_int,
        "ttc": ttc
    }

# ---------------- SUGGESTION GENERATOR (validated) ----------------
def generate_stronger_alternatives(pw: str, top_n: int = 3) -> List[Dict]:
    """
    Produce suggestions that are validated against the same estimator.
    Prefer strong random/diceware-hybrid options; avoid producing word-like outputs.
    """
    alternatives = []
    tried = set()

    def build_random_high_entropy(length=24) -> str:
        pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + SYMBOLS
        return "".join(secrets.choice(pool) for _ in range(length))

    # Try to generate validated strong suggestions
    attempts = 0
    while len(alternatives) < top_n and attempts < SUGGESTION_ATTEMPTS:
        attempts += 1
        strat = secrets.randbelow(3)
        if strat == 0:
            cand = build_random_high_entropy(length=24)
        elif strat == 1:
            # diceware-like but inject unpredictable digits/symbols
            words = [secrets.choice(RARE_WORDS).capitalize() for _ in range(3)]
            sep = secrets.choice(["-", "_", ".", ""])
            cand = sep.join(words)
            pos = max(1, len(cand)//2)
            cand = cand[:pos] + str(secrets.randbelow(90)+10) + secrets.choice(SYMBOLS) + cand[pos:]
        else:
            # hybrid: rareword + random chunk + symbol
            w = secrets.choice(RARE_WORDS).capitalize()
            rand = build_random_high_entropy(length=10)
            cand = f"{w}{secrets.choice(SYMBOLS)}{rand}"

        if cand in tried:
            continue
        tried.add(cand)

        # validate candidate: must not be word-like and should meet guess threshold
        if looks_word_like(cand):
            continue

        g = estimate_guesses_improved(cand)
        g_int = int(min(max(1, round(g)), MAX_GUESSES))

        # Accept if strong enough, otherwise keep as fallback
        if g_int >= STRONG_SUGGESTION_GUESSES:
            alternatives.append({
                "example": cand,
                "score": clamp_score_from_guesses(g_int),
                "label": score_label(clamp_score_from_guesses(g_int)),
                "ttc": pretty_time_to_crack(g_int),
                "why": "auto-generated strong password",
                "cost": "replace"
            })
        else:
            # keep as fallback candidate but mark appropriately
            alternatives.append({
                "example": cand,
                "score": clamp_score_from_guesses(g_int),
                "label": score_label(clamp_score_from_guesses(g_int)),
                "ttc": pretty_time_to_crack(g_int),
                "why": "auto-generated (did not meet strict strong threshold)",
                "cost": "replace"
            })

    # dedupe + sort by score desc
    uniq = {}
    for a in alternatives:
        uniq[a["example"]] = a
    sorted_alts = sorted(uniq.values(), key=lambda x: x["score"], reverse=True)

    # fallback: if nothing produced, produce one guaranteed high-entropy random password
    if not sorted_alts:
        fallback = build_random_high_entropy(length=28)
        g = estimate_guesses_improved(fallback)
        g_int = int(min(max(1, round(g)), MAX_GUESSES))
        sorted_alts = [{
            "example": fallback,
            "score": clamp_score_from_guesses(g_int),
            "label": score_label(clamp_score_from_guesses(g_int)),
            "ttc": pretty_time_to_crack(g_int),
            "why": "fallback strong random",
            "cost": "replace"
        }]

    return sorted_alts[:top_n]

# ---------------- API MODELS ----------------
class CheckRequest(BaseModel):
    password: str
    leaked: bool = False

class SuggestionModel(BaseModel):
    example: str
    score: int
    label: str
    ttc: str
    why: str
    cost: str

class CheckResponse(BaseModel):
    score: int
    label: str
    reasons: List[str]
    entropy_bits: float
    guesses_estimate: int
    ttc: str
    suggestions: List[SuggestionModel]

@app.post("/check", response_model=CheckResponse)
def check_pw(req: CheckRequest):
    if len(req.password) > 4096:
        raise HTTPException(status_code=400, detail="password too long")
    base = score_and_explain(req.password, leaked=req.leaked)
    suggestions = generate_stronger_alternatives(req.password, top_n=3)
    # ensure integer types
    base["guesses_estimate"] = int(min(max(0, int(base.get("guesses_estimate", 0))), MAX_GUESSES))
    base["score"] = int(base.get("score", 0))
    base["suggestions"] = suggestions
    return base

# simple generator endpoint used by frontend
class GenReq(BaseModel):
    words: int = 3
    capitalize: bool = True
    add_symbol: bool = True

@app.post("/generate")
def gen_pass(req: GenReq):
    count = max(2, min(5, req.words))
    w = [secrets.choice(WORDS) for _ in range(count)]
    if req.capitalize:
        w = [x.capitalize() for x in w]
    pw = "".join(w)
    if req.add_symbol:
        pw += secrets.choice(SYMBOLS)
    return {"password": pw}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)


# ---------------- End of file ----------------