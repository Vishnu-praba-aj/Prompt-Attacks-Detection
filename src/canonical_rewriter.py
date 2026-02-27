# canonical_rewriter.py

import spacy
from sentence_transformers import SentenceTransformer, util

# Load once globally (important for performance)
nlp = spacy.load("en_core_web_sm")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# =========================
# Configuration
# =========================

SUSPICIOUS_VERBS = {
    "ignore", "override", "bypass", "disable",
    "remember", "execute", "follow"
}

REFERENTIAL_TOKENS = {
    "it", "that", "this", "those", "them"
}

RISK_KEYWORDS = {
    "ignore", "override", "bypass", "disable",
    "system", "safety", "instructions"
}

# =========================
# Memory Entity
# =========================

class MemoryEntity:
    def __init__(self, text, embedding, ent_type):
        self.text = text
        self.embedding = embedding
        self.type = ent_type  # "action" | "entity"

# =========================
# Extractors
# =========================

def extract_action(text):
    doc = nlp(text)
    for sent in doc.sents:
        root = sent.root
        if root.pos_ == "VERB" and root.lemma_.lower() in SUSPICIOUS_VERBS:
            return sent.text
    return None


def extract_noun_entity(text):
    doc = nlp(text)
    for chunk in doc.noun_chunks:
        if chunk.root.pos_ == "NOUN":
            return chunk.text
    return None


def has_reference(text):
    doc = nlp(text)
    return any(tok.text.lower() in REFERENTIAL_TOKENS for tok in doc)


# =========================
# Relatedness (Semantic)
# =========================

def is_related(prompt, memory, threshold=0.65):
    if has_reference(prompt):
        return True

    if not memory:
        return False

    emb = embedder.encode(prompt, convert_to_tensor=True)

    return any(
        util.cos_sim(emb, m.embedding).item() >= threshold
        for m in memory
    )


# =========================
# Canonical Rewrite
# =========================

def canonicalize_prompt(prompt, memory):
    if not memory:
        return prompt, None

    resolved = memory[-1].text
    rewritten = prompt

    for ref in REFERENTIAL_TOKENS:
        rewritten = rewritten.replace(ref, resolved)

    return rewritten, resolved


# =========================
# Metrics
# =========================

def reference_resolution_accuracy(original, rewritten):
    return int(original != rewritten)


def explicitness_gain(original, rewritten):
    before = sum(k in original.lower() for k in RISK_KEYWORDS)
    after = sum(k in rewritten.lower() for k in RISK_KEYWORDS)
    return (after - before) / (before + 1)


def semantic_faithfulness(original, rewritten):
    e1 = embedder.encode(original, convert_to_tensor=True)
    e2 = embedder.encode(rewritten, convert_to_tensor=True)
    return util.cos_sim(e1, e2).item()


def canonicalization_coverage(original, rewritten):
    return int(has_reference(original) and original != rewritten)


# =========================
# Main Rewriter Class
# =========================

class CanonicalPromptRewriter:

    def __init__(self):
        self.memory = []

    def process(self, prompt):

        memory_before = self.memory.copy()

        # Context isolation
        if not is_related(prompt, self.memory):
            self.memory.clear()

        rewritten, resolved = canonicalize_prompt(prompt, self.memory)

        # Memory update
        action = extract_action(prompt)
        if action:
            emb = embedder.encode(action, convert_to_tensor=True)
            self.memory.append(MemoryEntity(action, emb, "action"))
        else:
            noun = extract_noun_entity(prompt)
            if noun:
                emb = embedder.encode(noun, convert_to_tensor=True)
                self.memory.append(MemoryEntity(noun, emb, "entity"))

        memory_after = self.memory.copy()

        return {
            "original": prompt,
            "rewritten": rewritten,
            "resolved_reference": resolved,
            "metrics": {
                "RRA": reference_resolution_accuracy(prompt, rewritten),
                "EG": explicitness_gain(prompt, rewritten),
                "SF": semantic_faithfulness(prompt, rewritten),
                "CC": canonicalization_coverage(prompt, rewritten),
            },
            "memory_size": len(self.memory),
        }