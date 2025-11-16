"""
Phase 1 Tests - The Continental Access Control System
Tests for the basic terminal UI and menu system

Run these tests with: pytest test_phase1.py -v

The -v flag shows verbose output so you can see which tests pass/fail
"""

import pytest
from io import StringIO
import sys
from unittest.mock import patch
import final_project.main as main


class TestMenuDisplay:
    """Tests for the menu display functions"""

    def test_show_banner_displays(self, capsys):
        """Test that the banner displays correctly"""
        main.show_banner()
        captured = capsys.readouterr()

        assert "CONTINENTAL" in captured.out, "Banner should mention 'CONTINENTAL'"
        assert "HOTEL" in captured.out, "Banner should mention 'HOTEL'"
        print("✓ Banner displays correctly")

    def test_show_menu_displays_options(self, capsys):
        """Test that all menu options are displayed"""
        main.show_menu()
        captured = capsys.readouterr()

        assert "1" in captured.out, "Menu should show option 1"
        assert "2" in captured.out, "Menu should show option 2"
        assert "3" in captured.out, "Menu should show option 3"
        assert "Login" in captured.out or "login" in captured.out, "Menu should mention Login"
        assert "Register" in captured.out or "register" in captured.out, "Menu should mention Register"
        assert "Exit" in captured.out or "exit" in captured.out, "Menu should mention Exit"
        print("✓ All menu options display correctly")


class TestUserInput:
    """Tests for user input validation"""

    @patch('builtins.input', return_value='1')
    def test_get_user_choice_valid_input(self, mock_input):
        """Test that valid input (1, 2, or 3) is accepted"""
        choice = main.get_user_choice()
        assert choice in ['1', '2', '3'], f"Expected '1', '2', or '3', but got '{choice}'"
        print("✓ Valid input is accepted")

    @patch('builtins.input', side_effect=['invalid', '5', '2'])
    def test_get_user_choice_invalid_then_valid(self, mock_input, capsys):
        """Test that invalid input is rejected and user is prompted again"""
        choice = main.get_user_choice()
        captured = capsys.readouterr()

        assert choice == '2', f"Should eventually return '2', but got '{choice}'"
        assert 'invalid' in captured.out.lower() or 'error' in captured.out.lower(), \
            "Should show an error message for invalid input"
        print("✓ Invalid input is rejected and user is re-prompted")


class TestMenuHandlers:
    """Tests for the menu option handlers"""

    @patch('builtins.input', return_value='')
    def test_handle_login_displays_message(self, mock_input, capsys):
        """Test that login handler shows a placeholder message"""
        main.handle_login()
        captured = capsys.readouterr()

        assert len(captured.out) > 0, "Login handler should display something"
        assert 'Phase 3' in captured.out or 'coming' in captured.out.lower(), \
            "Should mention that login is coming in a future phase"
        print("✓ Login handler displays placeholder message")

    @patch('builtins.input', return_value='')
    def test_handle_register_displays_message(self, mock_input, capsys):
        """Test that register handler shows a placeholder message"""
        main.handle_register()
        captured = capsys.readouterr()

        assert len(captured.out) > 0, "Register handler should display something"
        assert 'Phase 2' in captured.out or 'coming' in captured.out.lower(), \
            "Should mention that registration is coming in a future phase"
        print("✓ Register handler displays placeholder message")

    def test_handle_exit_displays_message(self, capsys):
        """Test that exit handler shows a goodbye message"""
        main.handle_exit()
        captured = capsys.readouterr()

        assert len(captured.out) > 0, "Exit handler should display a goodbye message"
        assert 'goodbye' in captured.out.lower() or 'bye' in captured.out.lower() \
            or 'farewell' in captured.out.lower() or 'safe' in captured.out.lower(), \
            "Should show some kind of farewell message"
        print("✓ Exit handler displays goodbye message")


class TestMainLoop:
    """Tests for the main application loop"""

    @patch('builtins.input', side_effect=['', '3', ''])
    def test_run_application_can_exit(self, mock_input, capsys):
        """Test that the application can exit when user chooses option 3"""
        try:
            main.run_application()
            captured = capsys.readouterr()

            # Should have shown menu at least once
            assert 'CONTINENTAL' in captured.out or 'Menu' in captured.out, \
                "Application should display the menu"
            print("✓ Application can exit properly")
        except Exception as e:
            pytest.fail(f"Application should handle exit gracefully, but got error: {e}")

    @patch('builtins.input', side_effect=['', '1', '', '3', ''])
    def test_run_application_handles_login_choice(self, mock_input, capsys):
        """Test that choosing option 1 triggers the login handler"""
        main.run_application()
        captured = capsys.readouterr()

        assert 'Phase 3' in captured.out or 'Login' in captured.out, \
            "Choosing option 1 should trigger login handler"
        print("✓ Application handles login choice")

    @patch('builtins.input', side_effect=['', '2', '', '3', ''])
    def test_run_application_handles_register_choice(self, mock_input, capsys):
        """Test that choosing option 2 triggers the register handler"""
        main.run_application()
        captured = capsys.readouterr()

        assert 'Phase 2' in captured.out or 'Register' in captured.out, \
            "Choosing option 2 should trigger register handler"
        print("✓ Application handles register choice")


class TestCodeOrganization:
    """Tests for code quality and organization"""

    def test_functions_exist(self):
        """Test that all required functions are defined"""
        required_functions = [
            'show_banner',
            'show_menu',
            'get_user_choice',
            'handle_login',
            'handle_register',
            'handle_exit',
            'run_application'
        ]

        for func_name in required_functions:
            assert hasattr(main, func_name), f"Function '{func_name}' should be defined"
            assert callable(getattr(main, func_name)), f"'{func_name}' should be a function"

        print("✓ All required functions are defined")

    def test_functions_not_empty(self):
        """Test that key functions have actual implementation (not just 'pass')"""
        import inspect

        # These functions should have real code, not just 'pass'
        functions_to_check = ['show_menu', 'get_user_choice', 'handle_exit']

        for func_name in functions_to_check:
            func = getattr(main, func_name)
            source = inspect.getsource(func)

            # Remove comments and docstrings to check actual code
            lines = [line.strip() for line in source.split('\n')
                    if line.strip() and not line.strip().startswith('#')
                    and not line.strip().startswith('"""')
                    and not line.strip().startswith("'''")]

            # Should have more than just the function definition
            assert len(lines) > 2, f"Function '{func_name}' appears to be empty or only has 'pass'"

        print("✓ Functions have actual implementations")


if __name__ == "__main__":
    """
    Run tests with color output and verbose mode
    """
    pytest.main([__file__, "-v", "--color=yes"])
