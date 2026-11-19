namespace Xunit;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class FactAttribute : Microsoft.VisualStudio.TestTools.UnitTesting.TestMethodAttribute
{
    public new string? DisplayName { get; set; }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class TheoryAttribute : Microsoft.VisualStudio.TestTools.UnitTesting.TestMethodAttribute
{
    public new string? DisplayName { get; set; }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public class InlineDataAttribute : Attribute
{
    public object?[] Data { get; }
    public InlineDataAttribute(params object?[] data) => Data = data;
}

public static class Assert
{
    public static void True(bool condition, string? userMessage = null) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(condition, userMessage);

    public static void False(bool condition, string? userMessage = null) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsFalse(condition, userMessage);

    public static void Equal<T>(T expected, T actual) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(expected, actual);

    public static void NotEqual<T>(T notExpected, T actual) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreNotEqual(notExpected, actual);

    public static void NotNull(object? @object) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsNotNull(@object);

    public static void Null(object? @object) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsNull(@object);

    public static void Contains(string expectedSubstring, string actualString) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(actualString?.Contains(expectedSubstring) == true);

    public static void Contains(string expectedSubstring, string actualString, StringComparison comparison) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(actualString?.Contains(expectedSubstring, comparison) == true);

    public static void Contains<T>(T expectedItem, IEnumerable<T> collection) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(collection != null && collection.Contains(expectedItem));

    public static void DoesNotContain(string expectedSubstring, string actualString) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsFalse(actualString?.Contains(expectedSubstring) == true);

    public static void Throws<T>(Action action) where T : Exception => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.ThrowsException<T>(action);

    public static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception => 
        await Microsoft.VisualStudio.TestTools.UnitTesting.Assert.ThrowsExceptionAsync<T>(action);

    public static void Empty<T>(IEnumerable<T>? collection) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(0, collection?.Count() ?? 0);

    public static void NotEmpty<T>(IEnumerable<T>? collection) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue((collection?.Count() ?? 0) > 0);

    public static void Single<T>(IEnumerable<T>? collection) => 
        Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(1, collection?.Count() ?? 0);
}

