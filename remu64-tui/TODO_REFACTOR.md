Lost Functionality That Needs Re-implementation

1. Config Hot Reloading ⚠️

- Status: Partially broken
- Issue: Reload signal mechanism simplified to || false
- Impact: Config file changes no longer trigger UI updates
- Fix Needed: Implement proper reload signaling between provider and library

2. Symbol Resolution in UI ⚠️

- Status: Disabled
- Issue: Generic symbolizer interface not defined
- Impact: Stack view and instruction view only show raw addresses
- Fix Needed:
  - Define generic symbolizer trait for UI
  - Re-implement symbol resolution in stack/instruction display
  - Add pointer chain following with symbol names

3. Instruction Skip Toggle ⚠️

- Status: Logic incomplete
- Issue: Skip actions stored in app but not properly synchronized with provider
- Impact: 's' key toggle doesn't persist or affect execution
- Fix Needed: Implement bi-directional communication for instruction actions

4. Error Handling for Config Issues ⚠️

- Status: Simplified
- Issue: Config error status messages removed
- Impact: No UI feedback for config file problems
- Fix Needed: Re-add config error reporting mechanism

5. Dynamic Display Name Formatting ⚠️

- Status: Basic implementation
- Issue: Display name is just raw minidump path
- Impact: Less user-friendly UI header
- Fix Needed: Format display name with filename + function address

Compilation Issues Remaining

1. Memory Type Mismatch: CowMemory wrapper may need adjustment
2. Unused Imports: Need cleanup pass
3. Missing Clone Implementations: Some types may need Clone derives

Testing Needed

- Basic TUI functionality
- Trace navigation (up/down/page up/down)
- Panel switching (Tab/BackTab)
- Go to beginning/end ('g'/'G')
- Reset functionality ('r')
- Library API with custom providers
- Memory and CPU state display accuracy

The core time-travel debugging functionality should work, but the user experience features (symbols, config reload, skip
toggles) need restoration.
