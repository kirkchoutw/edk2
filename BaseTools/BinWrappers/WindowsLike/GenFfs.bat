@setlocal
@set ToolName=%~n0%
@%PYTHON_COMMAND% -I -S %BASE_TOOLS_PATH%\Source\Python\%ToolName%\%ToolName%.py %*
