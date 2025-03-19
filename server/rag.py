import re
import json
import ollama
import numpy as np
from typing import List, Dict


class PermissionRAG:
    def __init__(self, dataset_path: str):
        """Initialize the RAG system with the permissions dataset."""

        with open(dataset_path, "r") as f:
            self.permissions_explanations_map = json.load(f)
        self.embeddings_map = self._initialize_embeddings()
        self.SIMILARITY_THRESHOLD = 0.7
        self.UNKNOWN_PERMISSION_TEXT = (
            "No detailed information available for this permission in our database. "
            "Exercise caution and consider the permission's potential impact based on its name."
        )

    def _initialize_embeddings(self) -> Dict[str, List[float]]:
        """Create embeddings for all permissions in the dataset."""
        embeddings_map = {}
        for permission, explanation in self.permissions_explanations_map.items():
            embeddings_data = f"{permission}: {explanation}"
            embeddings_map[permission] = self._get_embedding(embeddings_data)
        return embeddings_map

    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding for a given text."""
        response = ollama.embeddings(model='nomic-embed-text', prompt=text)
        return response['embedding']

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        vec1, vec2 = np.array(vec1), np.array(vec2)
        return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))

    def _extract_database_risk_level(self, explanation: str) -> str:
        """
        Extract the risk level from the explanation text.
        """
        match = re.search(r"Risk Level (\w+)", explanation)
        if match:
            return match.group(1)
        else:
            return "UNKNOWN"

    def get_relevant_context(self, permission: Dict[str, str], top_k: int = 3) -> str:
        """
        Get relevant context for a single permission.
        """
        perm_name = permission['permission']

        # If exact permission found in our dataset
        if perm_name in self.permissions_explanations_map:
            explanation = self.permissions_explanations_map[perm_name]
            db_risk = self._extract_database_risk_level(explanation)
            return (
                f"Permission: {perm_name}\n"
                f"Database Risk Level: {db_risk.lower()}\n"
                f"Known Context: {explanation}\n"
            )
        else:
            # If no exact match, find similar permissions using embeddings
            perm_embedding = self._get_embedding(perm_name)
            similarities = {
                known_perm: self._cosine_similarity(
                    perm_embedding, known_embedding)
                for known_perm, known_embedding in self.embeddings_map.items()
            }

            # Sort using similarity score and get top-k similar permissions
            similar_perms = sorted(similarities.items(),
                                   key=lambda x: x[1], reverse=True)[:top_k]
            found_similar = False
            for similar_perm, similarity_score in similar_perms:
                if similarity_score > self.SIMILARITY_THRESHOLD:
                    found_similar = True
                    explanation = self.permissions_explanations_map.get(
                        similar_perm, "")
                    db_risk = self._extract_database_risk_level(explanation)
                    return (
                        f"Permission: {perm_name}\n"
                        f"Database Risk Level: {db_risk.lower()}\n"
                        f"Similar Permission: {similar_perm} (similarity: {similarity_score:.2f})\n"
                        f"Known Context: {explanation}\n"
                    )
            # If no similar permissions found above threshold, return unknown info text
            if not found_similar:
                return (
                    f"Permission: {perm_name}\n"
                    f"Database Risk Level: UNKNOWN\n"
                    f"Known Context: {self.UNKNOWN_PERMISSION_TEXT}\n"
                )

    def _format_context(self, perm_name: str, explanation: str) -> str:
        """Format the context string for a permission, excluding any provided risk level."""
        db_risk = self._extract_database_risk_level(explanation)
        return (
            f"Permission: {perm_name}\n"
            f"Database Risk Level: {db_risk}\n"
            f"Known Context: {explanation}\n"
        )
