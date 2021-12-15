# TrustBreaker
Python application for the identification of DNS-based vulnerable trust delegations

## Usage

usage: TrustBreaker.py [-h] [--input_file INPUT_FILE] [--fingerprints_path FINGERPRINTS_PATH] [--resolvers_path RESOLVERS_PATH] [--amass_config_path AMASS_CONFIG_PATH] [--output_dir OUTPUT_DIR] [--gandi_api_key GANDI_API_KEY] domain                                                          
                                                                                                                                                                                                                                                                                                  
positional arguments:                                                                                                                                                                                                                                                                             
  domain                Target domain you wish to examine.                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                  
optional arguments:                                                                                                                                                                                                                                                                               
  -h, --help            show this help message and exit                                                                                                                                                                                                                                           
  --input_file INPUT_FILE, -i INPUT_FILE                                                                                                                                                                                                                                                          
                        Read in list of known subdomains. No OSINT collection.          
                        
  --fingerprints_path FINGERPRINTS_PATH, -f FINGERPRINTS_PATH                                                                                                                                                                                                                                     
                        Full path to Subtake fingerprints file. Default is ./fingerprints.json      
                        
  --resolvers_path RESOLVERS_PATH, -r RESOLVERS_PATH                                                                                                                                                                                                                                              
                        Full path to the resolvers file. Default is ./resolvers.txt         
                        
  --amass_config_path AMASS_CONFIG_PATH, -a AMASS_CONFIG_PATH                                                                                                                                                                                                                                     
                        Full path to Amass config file. Default is ./amass_config.ini            
                        
  --output_dir OUTPUT_DIR, -o OUTPUT_DIR                                                                                                                                                                                                                                                          
                        Full path to write ouput. Default is ./               
                        
  --gandi_api_key GANDI_API_KEY, -k GANDI_API_KEY                                                                                                                                                                                                                                                 
                        Gandi v5 API key. Domain availability checking will not work without this 
                        
   ## Installation
   
   Installation can be done by the included install.sh script.
   TrustBreaker requires GO to be installed and included in the path to operate correctly.
