from .models import Domain, ToolResult

def save_tool_result(domain_name, tool_name, result_data):
    # Step 1: Check or create the Domain record
    domain, created = Domain.objects.get_or_create(name=domain_name)

    # Step 2: Save the result for the tool
    ToolResult.objects.create(
        domain=domain,
        tool_name=tool_name,
        result_data=result_data
    )

    return f"Result for {domain_name} with tool {tool_name} saved successfully!"
