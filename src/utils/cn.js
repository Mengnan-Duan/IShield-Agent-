/**
 * IShield — Class Utility
 * Merges class names, filtering falsy values.
 * Inspired by clsx / tailwind-merge patterns.
 */

/**
 * Merges class names with Tailwind utility class deduplication.
 * Usage: cn("px-4 py-2", isActive && "bg-blue-500", extraClasses)
 * @param  {...(string | boolean | null | undefined | object)} args
 * @returns {string}
 */
export function cn(...args) {
  const classes = [];

  for (const arg of args) {
    if (!arg) continue;

    if (typeof arg === "string") {
      classes.push(...arg.trim().split(/\s+/).filter(Boolean));
    } else if (Array.isArray(arg)) {
      const result = cn(...arg);
      if (result) classes.push(result);
    } else if (typeof arg === "object") {
      for (const [key, value] of Object.entries(arg)) {
        if (value) classes.push(key);
      }
    }
  }

  return [...new Set(classes)].join(" ");
}
