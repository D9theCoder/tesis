import sys
from llm.provider import get_llm
from langchain_core.messages import HumanMessage

def main():
    print("=== Simple LLM Endpoint Tester ===")
    print("Available providers: gpt4o, gemini, claude, llama")
    
    provider = input("Enter provider to test (default: gpt4o): ").strip()
    if not provider:
        provider = "gpt4o"
        
    try:
        # Initialize the model using our newly created factory
        llm = get_llm(provider)
        print(f"\n[+] Successfully initialized {provider} model.")
        print(f"[+] Using model configuration: {llm.__class__.__name__}")
    except Exception as e:
        print(f"\n[-] Error initializing provider '{provider}': {e}")
        print("Hint: Check if your .env file is properly configured with the correct API keys.")
        sys.exit(1)
        
    print("\nStart chatting! Type 'exit' or 'quit' to stop.")
    
    while True:
        try:
            user_input = input("\nYou: ")
            if user_input.lower() in ['exit', 'quit']:
                print("Exiting...")
                break
            if not user_input.strip():
                continue
                
            # Call the LLM
            response = llm.invoke([HumanMessage(content=user_input)])
            
            print(f"\n{provider.upper()}: {response.content}")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\n[-] Error during chat API call: {e}")

if __name__ == "__main__":
    main()
