# bg_remover.py
import os
from PIL import Image
import torch
import numpy as np
from transparent_background import Remover
import uuid

class BackgroundRemover:
    """
    Background removal class using InSPyReNet model from transparent-background package
    """
    def __init__(self, use_jit=False):
        # Initialize the Remover with JIT option
        self.remover = Remover(jit=use_jit)
    
    def remove_background(self, image_path, output_dir):
        """
        Remove background from image and save the result
        
        Args:
            image_path: Path to input image
            output_dir: Directory to save output image
            
        Returns:
            Path to processed image
        """
        try:
            # Load image
            img = Image.open(image_path).convert('RGB')
            
            # Process image with transparent-background
            # The InSPyReNet model is used internally by the remover
            processed_array = self.remover.process(
                img, 
                type='rgba'  # RGBA output with alpha channel
            )
            
            # Convert numpy array to PIL Image
            if isinstance(processed_array, np.ndarray):
                processed_img = Image.fromarray(np.uint8(processed_array * 255) if processed_array.dtype == np.float32 else processed_array)
            else:
                processed_img = processed_array  # In case it's already a PIL Image
            
            # Create unique filename
            filename = f"{uuid.uuid4()}.png"
            output_path = os.path.join(output_dir, filename)
            
            # Save processed image
            processed_img.save(output_path, format="PNG")
            
            return output_path
        except Exception as e:
            raise Exception(f"Error processing image: {str(e)}")
    
    def batch_process(self, image_paths, output_dir):
        """
        Process multiple images at once
        
        Args:
            image_paths: List of paths to input images
            output_dir: Directory to save output images
            
        Returns:
            List of paths to processed images
        """
        output_paths = []
        
        for path in image_paths:
            output_path = self.remove_background(path, output_dir)
            output_paths.append(output_path)
            
        return output_paths