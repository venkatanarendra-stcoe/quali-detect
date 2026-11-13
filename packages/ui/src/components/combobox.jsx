/* Keyboard operation lives on the combobox input (aria-activedescendant); options, the portal and the field frame
   only take pointer events. ComboboxAddRow result rows are focusable list items that remove on Delete/Backspace, so
   these jsx-a11y rules do not apply. */
/* eslint-disable jsx-a11y/click-events-have-key-events, jsx-a11y/interactive-supports-focus, jsx-a11y/no-static-element-interactions, jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AlertIcon, CheckIcon, ChevronIcon, LoaderIcon, PlusIcon, XIcon } from "./icons.jsx";

const join = (...parts) => parts.filter(Boolean).join(" ");

/**
 * @typedef {{ value: string, label: string, description?: string, disabled?: boolean, group?: string }} ComboboxOption
 */

/** Controlled when `value !== undefined`, otherwise uncontrolled from `defaultValue`. */
function useControllable(value, defaultValue, onChange) {
  const [inner, setInner] = useState(defaultValue);
  const controlled = value !== undefined;
  const current = controlled ? value : inner;
  const set = (next, option) => {
    if (!controlled) setInner(next);
    onChange?.(next, option);
  };
  return [current, set];
}

/** Fixed position of the portalled listbox under (or, when there is no room, above) its anchor. */
function usePopupPosition(open, anchorRef, popupRef) {
  const [pos, setPos] = useState(null);
  useLayoutEffect(() => {
    if (!open) return undefined;
    const update = () => {
      const anchor = anchorRef.current;
      if (!anchor) return;
      const r = anchor.getBoundingClientRect();
      const below = window.innerHeight - r.bottom - 8;
      const above = r.top - 8;
      const flip = below < 200 && above > below;
      const room = Math.max((flip ? above : below) - 4, 120);
      setPos({
        left: r.left,
        width: r.width,
        top: flip ? undefined : r.bottom + 4,
        bottom: flip ? window.innerHeight - r.top + 4 : undefined,
        maxHeight: Math.min(288, room),
      });
    };
    const onScroll = (e) => {
      if (popupRef.current?.contains(e.target)) return;
      update();
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [open, anchorRef, popupRef]);
  return open ? pos : null;
}

/**
 * Accessible select replacing the native `<select>`: ARIA 1.2 combobox (`role="combobox"` input, `aria-activedescendant`,
 * listbox of options) whose listbox is rendered in a PORTAL (position: fixed), so cards, tables and `overflow-hidden`
 * ancestors never clip it. Keyboard: ArrowUp/Down, Home/End, Enter selects, Escape closes (and is not passed on to an
 * enclosing dialog while open), Tab closes, type-ahead on a non-searchable select, Backspace removes the last chip in
 * multi mode. Options can be static (`options`), filtered locally, or loaded asynchronously (`loadOptions`, debounced,
 * with loading / empty / error+retry states). Forwards `ref` to the input, so React Hook Form `register`/`Controller`
 * can focus it; pass `invalid`, `aria-describedby`, `id`, `name`, `onBlur` from the field.
 *
 * Value: a string (single) or string[] (`multiple`). Controlled with `value` + `onChange(value, option)`, or
 * uncontrolled with `defaultValue`. Colours use tokens only (focus ring = `--ring`; no brand fill).
 * @param {{
 *   options?: ComboboxOption[], value?: string | string[] | null, defaultValue?: string | string[] | null,
 *   onChange?: (value: any, option?: ComboboxOption) => void, multiple?: boolean,
 *   loadOptions?: (query: string, ctx: { signal: AbortSignal }) => Promise<ComboboxOption[]>,
 *   onSearch?: (query: string) => void, debounceMs?: number, loading?: boolean, error?: string | boolean,
 *   onRetry?: () => void, searchable?: boolean, placeholder?: string, searchPlaceholder?: string,
 *   emptyText?: string, loadingText?: string, disabled?: boolean, clearable?: boolean, invalid?: boolean,
 *   required?: boolean, id?: string, name?: string, className?: string, "aria-label"?: string,
 *   "aria-labelledby"?: string, "aria-describedby"?: string, onBlur?: (e: FocusEvent) => void,
 *   onKeyDown?: (e: KeyboardEvent) => void, onOpenChange?: (open: boolean) => void,
 *   ref?: import("react").Ref<HTMLInputElement> }} props
 *   `searchable` defaults to true with `loadOptions`/`onSearch` or more than 7 options. With `onSearch` (options
 *   supplied by the parent) or `loadOptions`, filtering is the caller's job; otherwise options are filtered locally on
 *   label and description. `error` shows a message (true = generic) with Retry (`onRetry`, or re-running `loadOptions`).
 *   `onKeyDown` only receives keys the component did not handle (e.g. Enter while closed).
 */
export function Combobox({
  options = [],
  value,
  defaultValue,
  onChange,
  multiple = false,
  loadOptions,
  onSearch,
  debounceMs = 250,
  loading = false,
  error,
  onRetry,
  searchable,
  placeholder = "Select…",
  searchPlaceholder,
  emptyText = "No results",
  loadingText = "Loading…",
  disabled = false,
  clearable = false,
  invalid = false,
  required,
  id,
  name,
  className,
  "aria-label": ariaLabel,
  "aria-labelledby": ariaLabelledBy,
  "aria-describedby": ariaDescribedBy,
  onBlur,
  onKeyDown,
  onOpenChange,
  ref,
}) {
  const uid = useId();
  const inputId = id ?? `${uid}-input`;
  const listId = `${uid}-list`;
  const [selected, setSelected] = useControllable(
    value,
    defaultValue === undefined ? (multiple ? [] : null) : defaultValue,
    onChange,
  );
  const selectedValues = useMemo(() => {
    if (multiple) return Array.isArray(selected) ? selected : [];
    return selected == null || selected === "" ? [] : [selected];
  }, [selected, multiple]);

  const [open, setOpenState] = useState(false);
  const [query, setQuery] = useState("");
  const [activeValue, setActiveValue] = useState(null);
  const [remote, setRemote] = useState({ options: [], loading: false, error: null });
  const [retryTick, setRetryTick] = useState(0);
  const [seen, setSeen] = useState({});

  const inputRef = useRef(null);
  const anchorRef = useRef(null);
  const popupRef = useRef(null);
  const searchTimer = useRef(null);
  const typeBuffer = useRef({ text: "", timer: null });
  const isSearchable = searchable ?? Boolean(loadOptions || onSearch || options.length > 7);

  const setInputRef = (el) => {
    inputRef.current = el;
    if (typeof ref === "function") ref(el);
    else if (ref) ref.current = el;
  };

  const setOpen = (next) => {
    setOpenState(next);
    onOpenChange?.(next);
  };
  const openPopup = () => {
    if (open || disabled) return;
    setActiveValue(multiple ? null : (selectedValues[0] ?? null));
    if (loadOptions) setRemote((r) => ({ ...r, loading: true, error: null }));
    setOpen(true);
  };
  const closePopup = () => {
    if (!open) return;
    setOpen(false);
    setQuery("");
    if (onSearch && query) onSearch("");
  };

  /* async options: debounced, stale responses ignored via abort */
  useEffect(() => {
    if (!loadOptions || !open) return undefined;
    const controller = new AbortController();
    const timer = setTimeout(
      async () => {
        try {
          const result = await loadOptions(query, { signal: controller.signal });
          if (controller.signal.aborted) return;
          setRemote({ options: result, loading: false, error: null });
          setSeen((s) => ({ ...s, ...Object.fromEntries(result.map((o) => [o.value, o])) }));
        } catch (err) {
          if (controller.signal.aborted) return;
          setRemote((r) => ({
            ...r,
            loading: false,
            error: err instanceof Error && err.message ? err.message : true,
          }));
        }
      },
      query ? debounceMs : 0,
    );
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [loadOptions, open, query, debounceMs, retryTick]);

  useEffect(
    () => () => {
      clearTimeout(searchTimer.current);
      clearTimeout(typeBuffer.current.timer);
    },
    [],
  );

  const source = loadOptions ? remote.options : options;
  const isLoading = loadOptions ? remote.loading : loading;
  const errorState = loadOptions ? remote.error : error;
  const serverFiltered = Boolean(loadOptions || onSearch);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list =
      serverFiltered || !q
        ? source
        : source.filter((o) => `${o.label} ${o.description ?? ""}`.toLowerCase().includes(q));
    // contiguous groups, in order of first appearance
    if (!list.some((o) => o.group)) return list;
    const order = [...new Set(list.map((o) => o.group ?? ""))];
    return order.flatMap((g) => list.filter((o) => (o.group ?? "") === g));
  }, [source, query, serverFiltered]);

  const labelOf = (v) =>
    (options.find((o) => o.value === v) ?? remote.options.find((o) => o.value === v) ?? seen[v])
      ?.label ?? String(v);
  const enabled = visible.filter((o) => !o.disabled);
  const active = visible.find((o) => o.value === activeValue && !o.disabled) ?? enabled[0] ?? null;
  const activeIndex = active ? visible.indexOf(active) : -1;
  const optionId = (index) => `${uid}-opt-${index}`;

  const pos = usePopupPosition(open, anchorRef, popupRef);

  useEffect(() => {
    if (!open || activeIndex < 0) return;
    document.getElementById(optionId(activeIndex))?.scrollIntoView({ block: "nearest" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, activeIndex]);

  /* Escape must close only the listbox: enclosing Radix dialogs/sheets listen for Escape on `document` in the capture
     phase, so claim the key earlier, on `window` in the capture phase, while this listbox is open. */
  const closeRef = useRef(closePopup);
  closeRef.current = closePopup;
  useEffect(() => {
    if (!open) return undefined;
    const onEscape = (e) => {
      if (e.key !== "Escape" || document.activeElement !== inputRef.current) return;
      e.stopPropagation();
      e.preventDefault();
      closeRef.current();
    };
    window.addEventListener("keydown", onEscape, true);
    return () => window.removeEventListener("keydown", onEscape, true);
  }, [open]);

  const select = (option) => {
    if (!option || option.disabled || disabled) return;
    setSeen((s) => ({ ...s, [option.value]: option }));
    if (multiple) {
      const next = selectedValues.includes(option.value)
        ? selectedValues.filter((v) => v !== option.value)
        : [...selectedValues, option.value];
      setSelected(next, option);
      setQuery("");
      setActiveValue(option.value);
    } else {
      setSelected(option.value, option);
      closePopup();
    }
  };
  const remove = (v) =>
    setSelected(
      selectedValues.filter((x) => x !== v),
      undefined,
    );
  const clear = () => {
    setSelected(multiple ? [] : null, undefined);
    setQuery("");
  };

  const move = (delta) => {
    if (!enabled.length) return;
    const at = enabled.indexOf(active);
    const next = enabled[Math.min(Math.max(at + delta, 0), enabled.length - 1)];
    setActiveValue(next.value);
  };

  const typeAhead = (char) => {
    const buf = typeBuffer.current;
    clearTimeout(buf.timer);
    buf.text += char.toLowerCase();
    buf.timer = setTimeout(() => (buf.text = ""), 700);
    const match = enabled.find((o) => o.label.toLowerCase().startsWith(buf.text));
    if (!open) openPopup();
    if (match) setActiveValue(match.value);
  };

  const handleKeyDown = (e) => {
    if (disabled) return;
    const { key } = e;
    if (key === "ArrowDown" || key === "ArrowUp") {
      e.preventDefault();
      if (!open) openPopup();
      else move(key === "ArrowDown" ? 1 : -1);
    } else if (open && (key === "Home" || key === "End")) {
      e.preventDefault();
      const target = key === "Home" ? enabled[0] : enabled[enabled.length - 1];
      if (target) setActiveValue(target.value);
    } else if (key === "Enter") {
      if (open) {
        e.preventDefault();
        select(active);
      } else onKeyDown?.(e);
    } else if (key === "Escape") {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        closePopup();
      }
    } else if (key === "Tab") {
      closePopup();
    } else if (key === "Backspace" && multiple && !query && selectedValues.length) {
      remove(selectedValues[selectedValues.length - 1]);
    } else if (!isSearchable && key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      if (key === " " && !typeBuffer.current.text) {
        if (open) select(active);
        else openPopup();
      } else typeAhead(key);
    } else onKeyDown?.(e);
  };

  const handleInput = (e) => {
    const next = e.target.value;
    setQuery(next);
    setActiveValue(null);
    if (loadOptions) setRemote((r) => ({ ...r, loading: true, error: null }));
    if (!open) openPopup();
    if (onSearch) {
      clearTimeout(searchTimer.current);
      searchTimer.current = setTimeout(() => onSearch(next), debounceMs);
    }
  };

  const triggerMouseDown = (e) => {
    if (disabled || e.target === inputRef.current) return;
    e.preventDefault();
    inputRef.current?.focus();
    if (open) closePopup();
    else openPopup();
  };

  const hasValue = selectedValues.length > 0;
  const singleLabel = !multiple && hasValue ? labelOf(selectedValues[0]) : "";
  const inputValue = multiple
    ? isSearchable
      ? query
      : ""
    : isSearchable && open
      ? query
      : singleLabel;
  const inputPlaceholder = multiple
    ? hasValue
      ? ""
      : placeholder
    : isSearchable && open && hasValue
      ? singleLabel
      : hasValue
        ? ""
        : placeholder;
  const showPlaceholderText = inputPlaceholder || (open && searchPlaceholder);

  let lastGroup;
  const rows = visible.map((o, index) => {
    const heading = o.group && o.group !== lastGroup ? o.group : null;
    lastGroup = o.group;
    const isSelected = selectedValues.includes(o.value);
    const isActive = index === activeIndex;
    return (
      <div key={o.value} role="presentation">
        {heading ? (
          <div
            role="presentation"
            className="px-2 pt-2 pb-1 text-xs font-medium text-muted-foreground"
          >
            {heading}
          </div>
        ) : null}
        <div
          id={optionId(index)}
          role="option"
          aria-selected={isSelected}
          aria-disabled={o.disabled || undefined}
          data-active={isActive || undefined}
          onClick={() => select(o)}
          onMouseMove={() => !o.disabled && !isActive && setActiveValue(o.value)}
          className={join(
            "flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm",
            isActive && "bg-accent text-accent-foreground",
            o.disabled && "cursor-not-allowed opacity-50",
          )}
        >
          <span className="min-w-0 flex-1">
            <span className="block truncate">{o.label}</span>
            {o.description ? (
              <span className="block truncate text-xs text-muted-foreground">{o.description}</span>
            ) : null}
          </span>
          {isSelected ? <CheckIcon className="size-4 shrink-0" /> : null}
        </div>
      </div>
    );
  });

  const popup =
    open && pos
      ? createPortal(
          <div
            ref={popupRef}
            data-combobox-popup=""
            onMouseDown={(e) => e.preventDefault()}
            onPointerDown={(e) => e.stopPropagation()}
            style={{
              position: "fixed",
              left: pos.left,
              top: pos.top,
              bottom: pos.bottom,
              width: pos.width,
              maxHeight: pos.maxHeight,
              pointerEvents: "auto",
            }}
            className="z-[60] flex flex-col overflow-hidden rounded-md border border-border bg-popover text-popover-foreground shadow-md"
          >
            <div
              className="qm-scroll min-h-0 flex-1 overflow-y-auto p-1"
              style={{ scrollBehavior: "auto" }}
            >
              {isLoading ? (
                <div
                  role="status"
                  className="flex items-center gap-2 px-2 py-2 text-sm text-muted-foreground"
                >
                  <LoaderIcon className="size-4 animate-spin" />
                  {loadingText}
                </div>
              ) : null}
              {errorState && !isLoading ? (
                <div role="alert" className="flex items-center gap-2 px-2 py-2 text-sm">
                  <AlertIcon className="size-4 shrink-0 text-status-danger" />
                  <span className="min-w-0 flex-1">
                    {typeof errorState === "string" ? errorState : "Could not load options."}
                  </span>
                  <button
                    type="button"
                    onClick={() => (loadOptions ? setRetryTick((t) => t + 1) : onRetry?.())}
                    className="rounded-sm px-1.5 py-0.5 text-sm font-medium underline outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    Retry
                  </button>
                </div>
              ) : null}
              {!isLoading && !errorState && visible.length === 0 ? (
                <div role="status" className="px-2 py-2 text-sm text-muted-foreground">
                  {emptyText}
                </div>
              ) : null}
              <div
                id={listId}
                role="listbox"
                aria-label={ariaLabel}
                aria-labelledby={ariaLabelledBy}
                aria-multiselectable={multiple || undefined}
              >
                {rows}
              </div>
            </div>
          </div>,
          document.body,
        )
      : null;

  return (
    <div className={join("relative min-w-0", className)}>
      <div
        ref={anchorRef}
        onMouseDown={triggerMouseDown}
        data-invalid={invalid || undefined}
        className={join(
          "flex min-h-9 w-full cursor-pointer items-center gap-1 rounded-sm border border-input bg-secondary pr-2 pl-2 text-sm text-foreground",
          multiple && "flex-wrap py-1",
          "focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 focus-within:ring-offset-background",
          invalid && "border-destructive",
          disabled && "cursor-not-allowed opacity-50",
        )}
      >
        {multiple
          ? selectedValues.map((v) => (
              <span
                key={v}
                className="inline-flex max-w-full items-center gap-1 rounded-sm border border-border bg-muted py-0.5 pr-0.5 pl-2 text-xs"
              >
                <span className="truncate">{labelOf(v)}</span>
                <button
                  type="button"
                  tabIndex={-1}
                  disabled={disabled}
                  aria-label={`Remove ${labelOf(v)}`}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                  }}
                  onClick={() => remove(v)}
                  className="rounded-sm p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <XIcon className="size-3" />
                </button>
              </span>
            ))
          : null}
        <input
          ref={setInputRef}
          id={inputId}
          type="text"
          role="combobox"
          autoComplete="off"
          spellCheck={false}
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-controls={open ? listId : undefined}
          aria-activedescendant={open && activeIndex >= 0 ? optionId(activeIndex) : undefined}
          aria-autocomplete={isSearchable ? "list" : "none"}
          aria-label={ariaLabel}
          aria-labelledby={ariaLabelledBy}
          aria-describedby={ariaDescribedBy}
          aria-invalid={invalid || undefined}
          aria-required={required || undefined}
          aria-busy={isLoading || undefined}
          readOnly={!isSearchable}
          disabled={disabled}
          value={inputValue}
          placeholder={(open && searchPlaceholder) || inputPlaceholder}
          onChange={handleInput}
          onKeyDown={handleKeyDown}
          onClick={() => (open && !isSearchable ? closePopup() : openPopup())}
          onBlur={(e) => {
            closePopup();
            onBlur?.(e);
          }}
          className={join(
            "h-7 min-w-[6ch] flex-1 cursor-[inherit] bg-transparent px-1 text-sm text-foreground outline-none placeholder:text-muted-foreground focus-visible:outline-none",
            !showPlaceholderText && "placeholder:opacity-0",
            !isSearchable && "caret-transparent select-none",
            "truncate",
          )}
        />
        {clearable && hasValue && !disabled ? (
          <button
            type="button"
            tabIndex={-1}
            aria-label="Clear selection"
            onMouseDown={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onClick={clear}
            className="rounded-sm p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <XIcon className="size-4" />
          </button>
        ) : null}
        <ChevronIcon
          className={join(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
        />
      </div>
      {name
        ? selectedValues.map((v) => <input key={v} type="hidden" name={name} value={v} />)
        : null}
      {popup}
    </div>
  );
}

/**
 * Multi-value combobox: chips in the field, Backspace on an empty search removes the last chip, each chip has a
 * remove button. Same props as {@link Combobox} with `multiple`; `value`/`defaultValue` are string arrays.
 * @param {Omit<Parameters<typeof Combobox>[0], "multiple">} props
 */
export function MultiSelect(props) {
  return <Combobox {...props} multiple />;
}

/**
 * "Add row" picker for members and roles: `[type] · subject combobox · [role] · Add`, with a removable result list
 * below. The type and role selectors are optional (omit `typeOptions` / `roleOptions`). The subject options come from
 * `optionsByType[type]` or `loadOptions(query, { type, signal })`. Items are `{ key, type, value, label, role,
 * roleLabel }`; duplicates (same type, value and role) are refused with a visible inline message. `validateAdd(item)` may
 * return a message to refuse an item. With `roleOptions` an Add needs a chosen role (`defaultRole` or the selector).
 * Enter in the closed subject field adds. Rows are focusable: Delete or Backspace on a focused row removes it, and the
 * remove button works with Enter/Space. After Add focus returns to the subject field; after Remove it moves to the
 * neighbouring row, or to the subject field when the list is empty. Adds and removals are announced in a live region.
 * The list scrolls inside `listMaxHeight` (a CSS length) so long lists never push the page around. Controlled with
 * `items` + `onItemsChange`, or uncontrolled with `defaultItems`.
 * @param {{
 *   typeOptions?: ComboboxOption[], defaultType?: string, optionsByType?: Record<string, ComboboxOption[]>,
 *   loadOptions?: (query: string, ctx: { type?: string, signal: AbortSignal }) => Promise<ComboboxOption[]>,
 *   roleOptions?: ComboboxOption[], defaultRole?: string, rolePlaceholder?: string, roleLoading?: boolean,
 *   items?: Array<object>, defaultItems?: Array<object>,
 *   onItemsChange?: (items: Array<object>) => void, onAdd?: (item: object) => void, onRemove?: (item: object) => void,
 *   validateAdd?: (item: object) => string | null | undefined, listMaxHeight?: string,
 *   subjectLabel?: string, subjectPlaceholder?: string, addLabel?: string, listLabel?: string,
 *   emptyListText?: string, disabled?: boolean, className?: string }} props
 */
export function ComboboxAddRow({
  typeOptions,
  defaultType,
  optionsByType,
  loadOptions,
  roleOptions,
  defaultRole,
  rolePlaceholder = "Choose a role",
  roleLoading = false,
  items,
  defaultItems = [],
  onItemsChange,
  onAdd,
  onRemove,
  validateAdd,
  listMaxHeight = "18rem",
  subjectLabel = "Member",
  subjectPlaceholder = "Search…",
  addLabel = "Add",
  listLabel = "Added",
  emptyListText = "Nothing added yet.",
  disabled = false,
  className,
}) {
  const [type, setType] = useState(
    defaultType ?? (typeOptions?.find((t) => !t.disabled) ?? typeOptions?.[0])?.value,
  );
  const [role, setRole] = useState(defaultRole);
  const [subject, setSubject] = useState(null);
  const [message, setMessage] = useState("");
  const [problem, setProblem] = useState("");
  const [list, setList] = useControllable(items, defaultItems, onItemsChange);
  const subjectRef = useRef(null);
  const rowRefs = useRef(new Map());
  const problemId = useId();

  const subjectOptions = loadOptions ? undefined : (optionsByType?.[type] ?? []);
  const boundLoad = useMemo(
    () => (loadOptions ? (query, ctx) => loadOptions(query, { ...ctx, type }) : undefined),
    [loadOptions, type],
  );
  const needsRole = Boolean(roleOptions) && !role;

  const add = () => {
    if (!subject || needsRole || disabled) return;
    const key = `${type ?? ""}:${subject.value}:${role ?? ""}`;
    const item = {
      key,
      type,
      value: subject.value,
      label: subject.label,
      role,
      roleLabel: roleOptions?.find((r) => r.value === role)?.label,
    };
    const refusal = list.some((i) => i.key === key)
      ? "This access is already in the list."
      : validateAdd?.(item);
    if (refusal) {
      setProblem(refusal);
      setMessage(refusal);
      return;
    }
    setProblem("");
    setList([...list, item]);
    onAdd?.(item);
    setMessage(`${subject.label} added.`);
    setSubject(null);
    subjectRef.current?.focus();
  };
  const removeItem = (item) => {
    const index = list.findIndex((i) => i.key === item.key);
    const rest = list.filter((i) => i.key !== item.key);
    setList(rest);
    onRemove?.(item);
    setProblem("");
    setMessage(`${item.label} removed.`);
    const neighbour = rest[Math.min(index, rest.length - 1)];
    // Wait for the list to re-render before moving focus.
    requestAnimationFrame(() => {
      (neighbour ? rowRefs.current.get(neighbour.key) : subjectRef.current)?.focus();
    });
  };

  return (
    <div className={join("min-w-0", className)}>
      <div className="flex flex-wrap items-center gap-2">
        {typeOptions ? (
          <Combobox
            className="w-28 shrink-0"
            aria-label={`${subjectLabel} type`}
            options={typeOptions}
            value={type ?? null}
            onChange={(v) => {
              setType(v);
              setSubject(null);
              setProblem("");
            }}
            searchable={false}
            disabled={disabled}
          />
        ) : null}
        <Combobox
          ref={subjectRef}
          className="min-w-52 flex-1"
          aria-label={subjectLabel}
          aria-describedby={problem ? problemId : undefined}
          invalid={Boolean(problem)}
          placeholder={subjectPlaceholder}
          key={type}
          options={subjectOptions}
          loadOptions={boundLoad}
          value={subject?.value ?? null}
          onChange={(_v, option) => {
            setSubject(option ?? null);
            setProblem("");
          }}
          searchable
          disabled={disabled}
          onKeyDown={(e) => {
            if (e.key === "Enter" && subject) {
              e.preventDefault();
              add();
            }
          }}
        />
        {roleOptions ? (
          <Combobox
            className="w-40 shrink-0"
            aria-label="Role"
            placeholder={roleLoading ? "Loading roles…" : rolePlaceholder}
            options={roleOptions}
            value={role ?? null}
            onChange={(v) => setRole(v || undefined)}
            searchable={false}
            disabled={disabled || roleLoading}
          />
        ) : null}
        <button
          type="button"
          onClick={add}
          disabled={!subject || needsRole || disabled}
          className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-sm border border-border-strong bg-secondary px-3 text-sm font-medium text-secondary-foreground outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50"
        >
          <PlusIcon className="size-4" />
          {addLabel}
        </button>
      </div>
      {problem ? (
        <p id={problemId} className="mt-1.5 text-xs text-status-danger">
          {problem}
        </p>
      ) : null}
      <p role="status" aria-live="polite" className="sr-only">
        {message}
      </p>
      <ul
        aria-label={listLabel}
        style={{ maxHeight: listMaxHeight }}
        className="qm-scroll mt-3 divide-y divide-border overflow-y-auto rounded-md border border-border"
      >
        {list.length === 0 ? (
          <li className="px-3 py-2 text-sm text-muted-foreground">{emptyListText}</li>
        ) : (
          list.map((item) => (
            <li
              key={item.key}
              ref={(node) => {
                if (node) rowRefs.current.set(item.key, node);
                else rowRefs.current.delete(item.key);
              }}
              tabIndex={0}
              onKeyDown={(e) => {
                if (disabled || (e.key !== "Delete" && e.key !== "Backspace")) return;
                e.preventDefault();
                removeItem(item);
              }}
              className="flex items-center gap-2 px-3 py-1.5 text-sm outline-none focus-visible:bg-accent focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
            >
              <span className="min-w-0 flex-1 truncate" title={item.label}>
                {item.label}
              </span>
              {item.type && typeOptions ? (
                <span className="shrink-0 text-xs text-muted-foreground">
                  {typeOptions.find((t) => t.value === item.type)?.label ?? item.type}
                </span>
              ) : null}
              {item.roleLabel ? (
                <span
                  className="max-w-40 shrink-0 truncate rounded-sm border border-border px-1.5 py-0.5 text-xs"
                  title={item.roleLabel}
                >
                  {item.roleLabel}
                </span>
              ) : null}
              <button
                type="button"
                aria-label={`Remove ${item.label}${item.roleLabel ? ` (${item.roleLabel})` : ""}`}
                disabled={disabled}
                onClick={() => removeItem(item)}
                className="shrink-0 rounded-sm p-1 text-muted-foreground outline-none hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
              >
                <XIcon className="size-4" />
              </button>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
