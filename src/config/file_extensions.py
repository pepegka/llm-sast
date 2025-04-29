# """                                                                            
#  Lists of file extensions / filenames that the scanner treats specially.        
#  Keeping them in a separate module avoids circular imports between services.    
#  """                                                                            
                                                                                
# Extensions that the FileService is allowed to analyse.                       
# Keep this list in-sync with EXTENSIONS sets that may exist in legacy scripts 
ALL_SCANNABLE: set[str] = {                                                    
    ".py", ".js", ".ts", ".go", ".java",                                       
    ".cpp", ".c", ".rs", ".php", ".rb",                                        
    ".sh", ".yaml", ".yml", ".json"                                            
}                                                                              
                                                                            
# Filenames that should be scanned even though they lack an extension.         
# NOTE: add or remove entries if your project requires different handling.     
SPECIAL_FILES: set[str] = {                                                    
    "Dockerfile",                                                              
    "Makefile",                                                                
    "Makefile.win",                                                            
    ".env",                                                                    
    "requirements.txt",                                                        
    "package.json",                                                            
}

PROGRAMMING_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".go", ".java",
    ".cpp", ".c", ".rs", ".php", ".rb"
}
