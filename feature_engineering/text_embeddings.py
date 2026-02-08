"""
Text embedding generation using Sentence-BERT.
Generates vector embeddings for banners, CVE descriptions, and commit messages.
"""

from typing import Dict, List, Optional, Any
import numpy as np
from sentence_transformers import SentenceTransformer
import pickle
from pathlib import Path

from config.settings import get_settings
from config.logging_config import get_logger

settings = get_settings()
logger = get_logger(__name__)


class TextEmbeddingGenerator:
    """
    Generates text embeddings using Sentence-BERT.
    """
    
    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize embedding generator.
        
        Args:
            model_name: Sentence-BERT model name (defaults to settings)
        """
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self.logger = logger
        self.model = None
        self.embedding_dim = None
        
        self._load_model()
    
    def _load_model(self):
        """Load Sentence-BERT model."""
        try:
            self.logger.info(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
            
            # Get embedding dimension
            test_embedding = self.model.encode("test")
            self.embedding_dim = len(test_embedding)
            
            self.logger.info(f"Model loaded. Embedding dimension: {self.embedding_dim}")
        
        except Exception as e:
            self.logger.error(f"Failed to load embedding model: {e}")
            self.logger.warning("Text embeddings will not be available")
            self.model = None
    
    def generate_embedding(self, text: Optional[str]) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Input text
        
        Returns:
            Embedding vector (or zeros if model not available)
        """
        if not text or not self.model:
            # Return zero vector if no text or model not loaded
            return np.zeros(self.embedding_dim or 384)  # Default to 384 for all-MiniLM-L6-v2
        
        try:
            # Clean text
            text = text.strip()
            if not text:
                return np.zeros(self.embedding_dim)
            
            # Truncate very long texts
            if len(text) > 5000:
                text = text[:5000]
            
            embedding = self.model.encode(text, convert_to_numpy=True)
            return embedding
        
        except Exception as e:
            self.logger.error(f"Error generating embedding: {e}")
            return np.zeros(self.embedding_dim)
    
    def generate_batch_embeddings(self, texts: List[str]) -> np.ndarray:
        """
        Generate embeddings for multiple texts (more efficient).
        
        Args:
            texts: List of input texts
        
        Returns:
            Array of embeddings
        """
        if not self.model:
            return np.zeros((len(texts), self.embedding_dim or 384))
        
        try:
            # Clean texts
            cleaned_texts = []
            for text in texts:
                if text:
                    text = text.strip()[:5000]  # Truncate
                    cleaned_texts.append(text if text else "")
                else:
                    cleaned_texts.append("")
            
            embeddings = self.model.encode(cleaned_texts, convert_to_numpy=True, show_progress_bar=False)
            return embeddings
        
        except Exception as e:
            self.logger.error(f"Error generating batch embeddings: {e}")
            return np.zeros((len(texts), self.embedding_dim))
    
    def generate_banner_embedding(self, banner: Optional[str]) -> Dict[str, Any]:
        """
        Generate embedding for service banner.
        
        Args:
            banner: Service banner text
        
        Returns:
            Dictionary with embedding and metadata
        """
        embedding = self.generate_embedding(banner)
        
        return {
            'banner_embedding': embedding,
            'banner_embedding_dim': len(embedding),
            'has_banner': 1.0 if banner else 0.0
        }
    
    def generate_cve_embedding(self, description: Optional[str]) -> Dict[str, Any]:
        """
        Generate embedding for CVE description.
        
        Args:
            description: CVE description text
        
        Returns:
            Dictionary with embedding and metadata
        """
        embedding = self.generate_embedding(description)
        
        return {
            'cve_embedding': embedding,
            'cve_embedding_dim': len(embedding),
            'has_cve_description': 1.0 if description else 0.0
        }
    
    def generate_commit_embedding(self, message: Optional[str]) -> Dict[str, Any]:
        """
        Generate embedding for commit message.
        
        Args:
            message: Commit message text
        
        Returns:
            Dictionary with embedding and metadata
        """
        embedding = self.generate_embedding(message)
        
        return {
            'commit_embedding': embedding,
            'commit_embedding_dim': len(embedding),
            'has_commit_message': 1.0 if message else 0.0
        }
    
    def extract_all_text_embeddings(
        self,
        asset_data: Dict[str, Any],
        cve_data: Optional[Dict[str, Any]] = None,
        exposure_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract all text embeddings from available data.
        
        Args:
            asset_data: Asset information
            cve_data: CVE information (if available)
            exposure_data: GitHub exposure information (if available)
        
        Returns:
            Dictionary of all text embeddings
        """
        features = {}
        
        # Banner embedding
        banner_features = self.generate_banner_embedding(asset_data.get('banner'))
        features.update(banner_features)
        
        # CVE description embedding
        if cve_data:
            cve_features = self.generate_cve_embedding(cve_data.get('description'))
            features.update(cve_features)
        else:
            features.update({
                'cve_embedding': np.zeros(self.embedding_dim or 384),
                'cve_embedding_dim': self.embedding_dim or 384,
                'has_cve_description': 0.0
            })
        
        # Commit message embedding (for GitHub exposures)
        if exposure_data and 'meta_data' in exposure_data:
            commit_msg = exposure_data['meta_data'].get('commit_message')
            commit_features = self.generate_commit_embedding(commit_msg)
            features.update(commit_features)
        else:
            features.update({
                'commit_embedding': np.zeros(self.embedding_dim or 384),
                'commit_embedding_dim': self.embedding_dim or 384,
                'has_commit_message': 0.0
            })
        
        return features
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of embeddings."""
        return self.embedding_dim or 384
    
    def save_cache(self, cache: Dict[str, np.ndarray], filepath: Optional[Path] = None):
        """
        Save embedding cache to disk.
        
        Args:
            cache: Dictionary mapping texts to embeddings
            filepath: Path to save cache
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'embedding_cache.pkl'
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            pickle.dump(cache, f)
        
        self.logger.info(f"Saved embedding cache ({len(cache)} entries) to {filepath}")
    
    def load_cache(self, filepath: Optional[Path] = None) -> Dict[str, np.ndarray]:
        """
        Load embedding cache from disk.
        
        Args:
            filepath: Path to load cache from
        
        Returns:
            Dictionary mapping texts to embeddings
        """
        if filepath is None:
            filepath = settings.MODEL_DIR / 'embedding_cache.pkl'
        
        if not filepath.exists():
            self.logger.warning(f"Cache file not found: {filepath}")
            return {}
        
        with open(filepath, 'rb') as f:
            cache = pickle.load(f)
        
        self.logger.info(f"Loaded embedding cache ({len(cache)} entries) from {filepath}")
        return cache
