#  """                                                                            
#  Configuration helpers that are imported by runtime code.                       
#  Currently this package only exposes lists of file-extensions / filenames       
#  used by the FileService to decide which files should be analysed.              
                                                                                
#  If additional configuration modules are required, add them here so that        
#  `from src.config import ...` keeps working.                                    
#  """                                                                            
from .file_extensions import ALL_SCANNABLE, SPECIAL_FILES                      
                                                                                
__all__ = ["ALL_SCANNABLE", "SPECIAL_FILES"]