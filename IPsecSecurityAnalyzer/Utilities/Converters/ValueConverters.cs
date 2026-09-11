using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Utilities.Converters;

/// <summary>
/// Converts boolean to Visibility, supporting Invert property and ConverterParameter="invert".
/// </summary>
public class BooleanToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; } = false;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = false;
        if (value is bool b)
        {
            flag = b;
        }
        else if (value is bool?)
        {
            flag = ((bool?)value).GetValueOrDefault();
        }

        bool invert = Invert;
        if (parameter is string paramStr && paramStr.Equals("invert", StringComparison.OrdinalIgnoreCase))
        {
            invert = !invert;
        }

        if (invert)
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is Visibility vis)
        {
            bool result = (vis == Visibility.Visible);
            if (Invert) result = !result;
            return result;
        }
        return false;
    }
}

/// <summary>
/// Converts null/not-null to Visibility.
/// </summary>
public class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; } = false;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool isNull = value == null || (value is string s && string.IsNullOrWhiteSpace(s));
        if (Invert) isNull = !isNull;
        return isNull ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Inverts boolean values for data binding.
/// </summary>
public class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return !b;
        }
        return false;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return !b;
        }
        return false;
    }
}

/// <summary>
/// Converts SeverityLevel or string to color brushes.
/// </summary>
public class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is SeverityLevel severity)
        {
            return severity switch
            {
                SeverityLevel.Critical => new SolidColorBrush(Color.FromRgb(239, 68, 68)),   // Red #EF4444
                SeverityLevel.High => new SolidColorBrush(Color.FromRgb(249, 115, 22)),      // Orange #F97316
                SeverityLevel.Medium => new SolidColorBrush(Color.FromRgb(234, 179, 8)),     // Yellow #EAB308
                SeverityLevel.Low => new SolidColorBrush(Color.FromRgb(59, 130, 246)),       // Blue #3B82F6
                _ => new SolidColorBrush(Color.FromRgb(156, 163, 175))                       // Gray #9CA3AF
            };
        }

        return new SolidColorBrush(Color.FromRgb(156, 163, 175));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Determines if a navigation button matches the currently active page and returns active styling brushes.
/// </summary>
public class ActivePageToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is NavigationPage currentPage && parameter is string pageString)
        {
            if (Enum.TryParse<NavigationPage>(pageString, out var targetPage) && currentPage == targetPage)
            {
                return new SolidColorBrush(Color.FromRgb(30, 41, 59)); // Active background #1E293B
            }
        }
        return Brushes.Transparent;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Determines if a navigation button matches the currently active page and returns border indicator brush.
/// </summary>
public class ActivePageToIndicatorBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is NavigationPage currentPage && parameter is string pageString)
        {
            if (Enum.TryParse<NavigationPage>(pageString, out var targetPage) && currentPage == targetPage)
            {
                return new SolidColorBrush(Color.FromRgb(6, 182, 212)); // Cyan #06B6D4
            }
        }
        return Brushes.Transparent;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
