import openai
import os
from dotenv import load_dotenv
from sglang import function, system, user, assistant, gen, set_default_backend, OpenAI
import subprocess

FIND_VULNERABILITY_PROMPT = f"""You are an expert security analyst who specializes in finding vulnerabilities in c code.
Given the following file of c code explain what the code does, identify any security vulnerabilities, and explain how to trigger them.
C code:
{{code}}"""

CREATE_TRIGGER_PROMPT = f"""Now create a test input which will trigger the vulnerability you identified.
The test input will be passed to the stdin of the c file you previously saw.
Only respond with the test input and no other text."""

CREATE_PATCH_PROMPT = f"""Update the code to fix the vulnerability you found.
Respond with the full updated file and no other text.
Be sure to respond with valid c syntax."""

def setup_env():
    load_dotenv()
    os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
    set_default_backend(OpenAI("gpt-4o-mini"))

def load_code_contents(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False

def trigger_vulnerability(trigger):
    try:
        with open('x.bin', 'w') as file:
            file.write(trigger)

        subprocess.run(['git', '-C', '../src/samples', 'reset', '--hard', 'HEAD'], check=True)
        subprocess.run(['../run.sh', '-x', 'build'], check=True)
        result = subprocess.run(['../run.sh', '-x', 'run_pov', '../security-llm/x.bin', 'filein_harness'], capture_output=True, text=True, check=True)
        if result.stderr and "ERROR: AddressSanitizer: global-buffer-overflow" in result.stderr:
                return True
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False

def run_tests():
    try:
        subprocess.run(['git', '-C', '../src/samples', 'reset', '--hard', 'HEAD'], check=True)
        subprocess.run(['../run.sh', '-x', 'build', '../security-llm/x.diff', 'samples'], check=True)
        
        result = subprocess.run(['../run.sh', '-x', 'run_tests'], capture_output=True, text=True, check=True)
        
        if 'FAILURE' in result.stdout or 'FAILURE' in result.stderr:
            return False
        
        return True
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False

def parse_code_from_ai_response(response):
    if response.startswith("```"):
        response = response[3:]
    if response.endswith("```"):
        response = response[:-3]
    if response.startswith("c\n"):
        response = response[2:]
    return response

def check_code_patch(patch):
    try:
        with open('mock_vp.c', 'w') as file:
            file.write(patch)

        result = subprocess.run(['git', 'diff', 'mock_vp.c'], capture_output=True, text=True, check=True)
        with open('x.diff', 'w') as file:
            file.write(result.stdout)
        
        return run_tests()
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False
    

@function
def agent(s, code):
    s += user(FIND_VULNERABILITY_PROMPT.format(code=code))
    s += assistant(gen("vulnerability_description", max_tokens=1000))
    s += user(CREATE_TRIGGER_PROMPT)
    s += assistant(gen("trigger", max_tokens=1000))
    s += user(CREATE_PATCH_PROMPT)
    s += assistant(gen("patch", max_tokens=1000))

if __name__ == "__main__":
    setup_env()
    while True:
        # TODO: add retry/error handling
        code = load_code_contents("../src/samples/mock_vp.c")
        if code is None:
            print("Error: Failed to load code contents.")
            break

        state = agent.run(code=code)

        if trigger_vulnerability(state["trigger"]):
            print("Vulnerability triggered")
        else:
            print("Vulnerability not triggered")
        
        if check_code_patch(parse_code_from_ai_response(state["patch"])):
            print("Patch applied successfully")
        else:
            print("Patch not applied")
        break
