import re
import json
import base64
import secrets
from pathlib import Path
import requests
import strictyaml


def encrypt_document(input_document: Path, output_json: Path, password: str):
    # Check if input document exists
    if not input_document.is_file():
        raise FileNotFoundError(f"Error: Input document {input_document} does not exist.")

    # Ensure the password is provided
    if not password:
        raise ValueError("Error: Password is required for encryption.")

    # Read and base64 encode the document
    document_content = base64.b64encode(input_document.read_bytes()).decode("utf-8")

    # Prepare the payload for the POST request
    payload = {"password": password, "document": document_content}  # Document is already base64 encoded

    # Send the POST request and capture the response
    try:
        response = requests.post(
            "http://127.0.0.1:49160/encrypt",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),  # Encode the payload using json library
        )
    except requests.exceptions.RequestException as e:
        raise ConnectionError(
            "Error: Unable to reach the encryption server. Please make sure the encryption server is running."
        ) from e

    # Clear the password from memory as soon as it's used
    del password

    # Check if the request was successful
    if response.status_code != 200:
        raise Exception(f"Error: Failed with status code {response.status_code}. Response: {response.text}")

    # Save the encrypted document and IV to the output JSON file
    output_json.write_text(response.text)

    print(f"Encryption completed successfully. Output saved to {output_json}.")


def check_file_for_layout(file_path: Path, layout_name: str, max_lines: int = -1) -> bool:
    try:
        not_read_all = max_lines > 0
        line_count = 0
        in_front_matter = False
        with file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not_read_all:
                    line_count += 1
                    if line_count > max_lines:
                        break
                if line.strip() == "---":
                    if not in_front_matter:
                        in_front_matter = True
                    else:
                        break
                elif in_front_matter:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if "layout" in key and layout_name in value:
                            return True
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return False


def find_index_files_with_layout(directory: Path, layout_name: str, max_lines: int = -1):
    matching_files: list[Path] = []
    for file_path in directory.rglob("*"):
        if file_path.name in ["index.html", "index.md"]:
            if check_file_for_layout(file_path, layout_name, max_lines):
                matching_files.append(file_path)
    return matching_files


def load_yaml_as_dict(file_path: Path):
    with open(file_path, "r") as file:
        file_str = file.read()
    parsed_data = strictyaml.load(file_str).data
    if isinstance(parsed_data, dict):
        return parsed_data
    else:
        raise RuntimeError(f"Failed to parse as dict: {file_path}")


def save_yaml_from_dict(file_path: Path, pydict: dict):
    yaml_str = strictyaml.as_document(pydict).as_yaml()
    with open(file_path, "w") as file:
        file.write(yaml_str)


def parse_option_tag(potential_tag: str) -> tuple[tuple[str, ...], dict[str, str]] | tuple[None, None]:
    potential_tag_copy = potential_tag.strip()
    if re.fullmatch(r"<.*>", potential_tag_copy):
        option_str = potential_tag_copy[1:-1]
        split_char = ":" if ":" in option_str else "="
        if not option_str:
            return (), {}
        option_list = [opt.strip() for opt in option_str.split(",")]
        option_args = tuple(opt for opt in option_list if split_char not in opt)
        option_kwargs = {
            k.strip(): v.strip() for k, v in [opt.split(split_char, 1) for opt in option_list if split_char in opt]
        }

        return option_args, option_kwargs
    else:
        return None, None


if __name__ == "__main__":

    cwd = Path(".").resolve()
    slp_idxs = find_index_files_with_layout(cwd, "shareable-link-protected", max_lines=50)
    slp_parents = [index.parent for index in slp_idxs]
    slp_titles = [parent.name for parent in slp_parents]
    slp_protected_idxs = [parent / "index-protected.html" for parent in slp_parents]

    password_config = cwd / "encrypt" / "slp_secrets.yaml"
    password_dict = load_yaml_as_dict(password_config)

    def generate_passwords(setup_error):
        generator_solution = {}
        for k, v in password_dict.items():
            use_random_password = False
            random_password_bytes = None
            if v:
                opt_args, opt_kwargs = parse_option_tag(v)
                if opt_args is not None and opt_kwargs is not None and not opt_args and not opt_kwargs:
                    # handles <>
                    use_random_password = True
                else:
                    if opt_args:
                        if "secret" in opt_args:
                            use_random_password = True
                        else:
                            setup_error += f"\nThere is an unknown argument in the option tag args:\n{opt_args}\n"
                            setup_error += "Currently only <secret> is supported.\n"
                    if opt_kwargs:
                        if "bytes" in opt_kwargs:
                            random_password_bytes = int(opt_kwargs["bytes"])
                        else:
                            setup_error += "\nThere is an unknown keyword argument in the option tag kwargs:"
                            setup_error += f"\n{opt_kwargs}\n"
                            setup_error += "Currently only <bytes:INT_CONVERTABLE> is supported.\n"
            else:
                use_random_password = True

            if use_random_password:
                if not setup_error:
                    generator_solution[k] = 32 if random_password_bytes is None else random_password_bytes

        if not setup_error:
            for key, nb in generator_solution.items():
                password_dict[key] = secrets.token_urlsafe(nbytes=nb)
            save_yaml_from_dict(password_config, password_dict)

        return setup_error

    def validate_setup():
        setup_error = ""
        for page in slp_protected_idxs:
            if not page.exists():
                setup_error += f"Missing page: {page}\n"

        for title in slp_titles:
            if title not in password_dict:
                setup_error += f"Missing the key in slp_secrets.yaml titled: {title}\n"
        setup_error = generate_passwords(setup_error)

        if setup_error:
            raise RuntimeError(f"Encryption setup validation failed:\n{setup_error}")

    validate_setup()

    def update_jekyll_config():
        jekyll_config = cwd / "_config.yaml"
        jekyll_dict = load_yaml_as_dict(jekyll_config)

        excl = jekyll_dict["exclude"]
        for page in slp_protected_idxs:
            rel_page = str(page.relative_to(cwd).as_posix())
            if rel_page not in excl:
                excl.append(rel_page)

        jekyll_dict.update({"exclude": excl})

        save_yaml_from_dict(jekyll_config, jekyll_dict)

    # update_jekyll_config()  # not necessary due to gitignore

    def encrypt_slp_protected_idxs():
        for page in slp_protected_idxs:
            json_file = page.parent / (page.stem + ".json")
            encrypt_document(page, json_file, password_dict[page.parent.name])

    encrypt_slp_protected_idxs()
