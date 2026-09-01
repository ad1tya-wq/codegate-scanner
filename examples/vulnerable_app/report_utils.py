def to_fahrenheit(celsius):
    """Safe: no SQL, shell, or credentials -- ordinary arithmetic."""
    return celsius * 9 / 5 + 32


def slugify(text):
    """Safe: string formatting only."""
    return text.lower().strip().replace(" ", "-")


def average(numbers):
    """Safe: pure computation, no external input reaches an interpreter."""
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)
