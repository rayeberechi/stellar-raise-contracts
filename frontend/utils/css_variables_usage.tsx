/**
 * @title CSS Variables Usage Utility
 * @notice Secure utility for CSS custom properties (CSS variables) handling
 * @dev Provides type-safe access to design tokens with validation and sanitization
 * @author Stellar Raise Security Team
 * @notice SECURITY: All CSS variable access must go through this utility to prevent
 *         CSS injection attacks and ensure variable name validation.
 */

/**
 * @notice Predefined list of allowed CSS variable names
 * @dev Only variables defined in this list can be accessed via the utility
 *      This prevents CSS injection through arbitrary variable names
 */
/**
 * @notice Predefined list of allowed CSS variable names
 * @dev Only variables defined in this list can be accessed via the utility
 *      This prevents CSS injection through arbitrary variable names
 */
export const ALLOWED_CSS_VARIABLES = [
  // Breakpoints
  '--breakpoint-mobile',
  '--breakpoint-tablet',

  // Brand Colors
  '--color-primary-blue',
  '--color-deep-navy',
  '--color-success-green',
  '--color-error-red',
  '--color-warning-orange',
  '--color-neutral-100',
  '--color-neutral-200',
  '--color-neutral-300',
  '--color-neutral-700',
  '--color-neutral-900',

  // Typography
  '--font-family-primary',
  '--font-size-xs',
  '--font-size-sm',
  '--font-size-base',
  '--font-size-lg',
  '--font-size-xl',
  '--font-size-2xl',
  '--font-size-3xl',

  // Spacing
  '--space-1',
  '--space-2',
  '--space-3',
  '--space-4',
  '--space-5',
  '--space-6',
  '--space-8',
  '--space-10',
  '--space-12',
  '--space-16',

  // Touch Targets
  '--touch-target-min',

  // Grid System
  '--grid-columns-mobile',
  '--grid-columns-tablet',
  '--grid-columns-desktop',
  '--grid-gutter-mobile',
  '--grid-gutter-tablet',
  '--grid-gutter-desktop',

  // Container
  '--container-mobile',
  '--container-tablet',
  '--container-desktop',

  // Z-index Scale
  '--z-base',
  '--z-dropdown',
  '--z-sticky',
  '--z-fixed',
  '--z-modal-backdrop',
  '--z-modal',
  '--z-toast',

  // Transitions
  '--transition-fast',
  '--transition-base',
  '--transition-slow',

  // Border Radius
  '--radius-sm',
  '--radius-md',
  '--radius-lg',
  '--radius-xl',
  '--radius-full',

  // Shadows
  '--shadow-sm',
  '--shadow-md',
  '--shadow-lg',
  '--shadow-xl',

  // Safe Area Insets
  '--safe-area-inset-top',
  '--safe-area-inset-right',
  '--safe-area-inset-bottom',
  '--safe-area-inset-left',

  // Documentation
  '--color-docs-bg',
  '--color-docs-text',
  '--color-docs-link',
  '--color-docs-accent',
  '--font-docs-code',
  '--space-docs-content',
] as const;

/**
 * @notice Type for allowed CSS variable names
 */
export type AllowedCssVariable = typeof ALLOWED_CSS_VARIABLES[number];

/**
 * @notice Regular expression for validating CSS variable names
 * @dev Ensures variable names start with -- and contain only valid characters
 */
const CSS_VAR_NAME_REGEX = /^--[a-zA-Z][a-zA-Z0-9-_]*$/;

/**
 * @notice Regular expression for detecting potentially malicious CSS values
 * @dev Blocks URL() references and expression() which could be used for attacks
 */
const DANGEROUS_CSS_PATTERN = /(?:url\s*\(|expression\s*|javascript:|data:text\/css|@import)/i;

/**
 * @notice Type for CSS variable value map
 */
export type CssVariablesMap = Partial<Record<AllowedCssVariable, string>>;

/**
 * @title CssVariablesError
 * @notice Custom error class for CSS variable related errors
 */
export class CssVariablesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CssVariablesError';
  }
}

/**
 * @title CssVariableValidator
 * @notice Static validator class for CSS variable operations
 */
export class CssVariableValidator {
  /**
   * @notice Validates if a CSS variable name is allowed
   * @param variableName The variable name to validate
   * @returns True if the variable is valid and allowed
   * @throws CssVariablesError if validation fails
   */
  static isValidVariableName(variableName: string): boolean {
    // Check format
    if (!CSS_VAR_NAME_REGEX.test(variableName)) {
      throw new CssVariablesError(
        `Invalid CSS variable name format: "${variableName}". Must start with "--" and contain only alphanumeric characters, hyphens, and underscores.`
      );
    }

    // Check against allowed list
    if (!ALLOWED_CSS_VARIABLES.includes(variableName as AllowedCssVariable)) {
      throw new CssVariablesError(
        `CSS variable "${variableName}" is not in the allowed list. Use getAllowedVariables() to see available variables.`
      );
    }

    return true;
  }

  /**
   * @notice Validates a CSS value for potential security issues
   * @param value The CSS value to validate
   * @returns True if the value is safe
   * @throws CssVariablesError if dangerous patterns are detected
   */
  static isValidValue(value: string): boolean {
    if (DANGEROUS_CSS_PATTERN.test(value)) {
      throw new CssVariablesError(
        `Potentially dangerous CSS value detected. URL(), expression(), and @import are not allowed for security reasons.`
      );
    }
    return true;
  }

  /**
   * @notice Returns the list of all allowed CSS variables
   * @returns Readonly array of allowed variable names
   */
  static getAllowedVariables(): readonly string[] {
    return ALLOWED_CSS_VARIABLES;
  }
}

/**
 * @title CssVariablesUsage
 * @notice Main utility class for secure CSS variable operations
 */
export class CssVariablesUsage {
  private element: HTMLElement;

  /**
   * @notice Creates a new CssVariablesUsage instance
   * @param element The HTML element to operate on (defaults to document.documentElement)
   */
  constructor(element?: HTMLElement) {
    this.element = element || document.documentElement;
  }

  /**
   * @notice Gets a CSS variable value securely
   * @param variableName The name of the CSS variable (with or without -- prefix)
   * @param fallback Optional fallback value if variable is not defined
   * @returns The computed value of the CSS variable
   * @throws CssVariablesError if variable name is invalid
   */
  get(variableName: string, fallback?: string): string {
    // Normalize variable name
    const normalizedName = this.normalizeVariableName(variableName);

    // Validate the variable name
    CssVariableValidator.isValidVariableName(normalizedName);

    // Get computed style
    const computedStyle = getComputedStyle(this.element);
    const value = computedStyle.getPropertyValue(normalizedName).trim();

    // Return value or fallback
    return value || fallback || '';
  }

  /**
   * @notice Sets a CSS variable value securely
   * @param variableName The name of the CSS variable
   * @param value The value to set
   * @throws CssVariablesError if variable name or value is invalid
   */
  set(variableName: string, value: string): void {
    // Normalize variable name
    const normalizedName = this.normalizeVariableName(variableName);

    // Validate the variable name
    CssVariableValidator.isValidVariableName(normalizedName);

    // Validate the value
    CssVariableValidator.isValidValue(value);

    // Set the property
    this.element.style.setProperty(normalizedName, value);
  }

  /**
   * @notice Removes a CSS variable
   * @param variableName The name of the CSS variable to remove
   * @throws CssVariablesError if variable name is invalid
   */
  remove(variableName: string): void {
    // Normalize variable name
    const normalizedName = this.normalizeVariableName(variableName);

    // Validate the variable name
    CssVariableValidator.isValidVariableName(normalizedName);

    // Remove the property
    this.element.style.removeProperty(normalizedName);
  }

  /**
   * @notice Gets multiple CSS variables at once
   * @param variableNames Array of variable names to retrieve
   * @param fallback Optional fallback value for undefined variables
   * @returns Object mapping variable names to their values
   * @throws CssVariablesError if any variable name is invalid
   */
  getMultiple(variableNames: string[], fallback?: string): CssVariablesMap {
    const result: CssVariablesMap = {};

    for (const name of variableNames) {
      const normalizedName = this.normalizeVariableName(name);
      CssVariableValidator.isValidVariableName(normalizedName);
      result[normalizedName as AllowedCssVariable] = this.get(name, fallback);
    }

    return result;
  }

  /**
   * @notice Sets multiple CSS variables at once
   * @param variables Object mapping variable names to values
   * @throws CssVariablesError if any variable name or value is invalid
   */
  setMultiple(variables: CssVariablesMap): void {
    for (const [name, value] of Object.entries(variables)) {
      if (value !== undefined) {
        this.set(name, value);
      }
    }
  }

  /**
   * @notice Checks if a CSS variable is defined
   * @param variableName The name of the CSS variable
   * @returns True if the variable is defined
   * @throws CssVariablesError if variable name is invalid
   */
  has(variableName: string): boolean {
    const normalizedName = this.normalizeVariableName(variableName);
    CssVariableValidator.isValidVariableName(normalizedName);
    return this.get(normalizedName) !== '';
  }

  /**
   * @notice Normalizes a CSS variable name
   * @dev Ensures the variable name has the -- prefix
   * @param variableName The variable name to normalize
   * @returns Normalized variable name with -- prefix
   */
  private normalizeVariableName(variableName: string): string {
    const trimmed = variableName.trim();
    return trimmed.startsWith('--') ? trimmed : `--${trimmed}`;
  }
}

/**
 * @title CSS Variable Hooks for React
 * @notice React hooks for CSS variable operations
 */

/**
 * @notice Gets a CSS variable value as a React hook
 * @param variableName The name of the CSS variable
 * @param fallback Optional fallback value
 * @returns The computed value of the CSS variable
 */
export function useCssVariable(variableName: string, fallback?: string): string {
  if (typeof window === 'undefined') {
    return fallback || '';
  }

  const cssVars = new CssVariablesUsage();
  return cssVars.get(variableName, fallback);
}

/**
 * @title Helper Functions
 */

/**
 * @notice Creates a CSS var() expression safely
 * @param variableName The CSS variable name
 * @param fallback Optional fallback value
 * @returns A formatted CSS var() expression
 */
export function cssVar(variableName: string, fallback?: string): string {
  // Validate the variable name
  const normalizedName = variableName.trim().startsWith('--')
    ? variableName.trim()
    : `--${variableName.trim()}`;
  
  CssVariableValidator.isValidVariableName(normalizedName);

  if (fallback !== undefined) {
    return `var(${normalizedName}, ${fallback})`;
  }
  return `var(${normalizedName})`;
}

/**
 * @notice Creates a CSS calc() expression with CSS variables
 * @param expression The calc expression
 * @returns The formatted calc expression
 */
export function cssCalc(expression: string): string {
  // Basic validation - ensure no dangerous patterns
  CssVariableValidator.isValidValue(expression);
  return `calc(${expression})`;
}

/**
 * @notice Gets a CSS variable value specifically tailored for documentation components.
 * @dev NatSpec: This React hook wrapper simplifies extracting documentation-specific 
 * design tokens. It guarantees that documentation styling variables are securely validated, 
 * maintaining architectural separation and reducing component clutter.
 * @custom:security Variables fetched via this hook still pass through the core validator 
 * preventing rogue values or untested variables from breaking documentation layout.
 * @param variableName The documentation CSS variable name to fetch.
 * @param fallback Optional fallback value if the documentation token is undefined.
 * @returns The computed styling value.
 */
export function useDocsCssVariable(variableName: string, fallback?: string): string {
  return useCssVariable(variableName, fallback);
}

// Default export for convenience
export default CssVariablesUsage;
