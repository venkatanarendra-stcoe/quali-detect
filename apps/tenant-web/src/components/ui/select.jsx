import { Children, Fragment, isValidElement } from "react";
import { Combobox } from "@qmentisai/ui";

/** Internal stand-in for the empty-string option value (the Combobox treats "" as "no selection"). */
const EMPTY = "__qm_empty__";

function textOf(node) {
  if (node == null || typeof node === "boolean") return "";
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (isValidElement(node)) return textOf(node.props.children);
  return String(node);
}

/** Flattens `<option>` children (including fragments and mapped arrays) into Combobox options. */
function collectOptions(children, out = []) {
  Children.forEach(children, (child) => {
    if (!isValidElement(child)) return;
    if (child.type === Fragment) collectOptions(child.props.children, out);
    else if (child.type === "option") {
      const raw = child.props.value ?? textOf(child.props.children);
      out.push({
        value: raw === "" ? EMPTY : String(raw),
        label: textOf(child.props.children),
        disabled: Boolean(child.props.disabled),
      });
    }
  });
  return out;
}

/**
 * Accessible select built on the shared `Combobox` (`@qmentisai/ui`). Keeps the former native-select call-site API:
 * `<option>` children, controlled `value` (string) and `onChange(event)` where `event.target.value` is the chosen string
 * (`""` for an empty option). An empty option is shown as the placeholder while nothing is chosen, and the control is clearable (Clear = the empty value).
 * For React Hook Form use `Controller` (`value`, `onChange`, `onBlur`, `ref`, `name`), not `register`.
 * @param {{ children?: import("react").ReactNode, value?: string, defaultValue?: string,
 *   onChange?: (event: { target: { value: string, name?: string, id?: string } }) => void,
 *   onBlur?: (e: FocusEvent) => void, disabled?: boolean, invalid?: boolean, "aria-invalid"?: boolean | string,
 *   id?: string, name?: string, className?: string, placeholder?: string,
 *   ref?: import("react").Ref<HTMLInputElement> } & Record<string, any>} props
 */
function Select({
  children,
  value,
  defaultValue,
  onChange,
  invalid,
  "aria-invalid": ariaInvalid,
  placeholder,
  ref,
  ...rest
}) {
  const options = collectOptions(children);
  const hasEmpty = options.some((o) => o.value === EMPTY);
  const toInner = (v) => (v === undefined ? undefined : v === "" || v === null ? null : String(v));
  const emit = (next) => {
    const v = next == null || next === EMPTY ? "" : next;
    onChange?.({ target: { value: v, name: rest.name, id: rest.id } });
  };
  return (
    <Combobox
      ref={ref}
      options={options}
      value={toInner(value)}
      defaultValue={toInner(defaultValue)}
      onChange={emit}
      clearable={hasEmpty}
      invalid={invalid ?? (ariaInvalid === true || ariaInvalid === "true")}
      placeholder={placeholder ?? options.find((o) => o.value === EMPTY)?.label ?? "Select…"}
      {...rest}
    />
  );
}

export { Select };
