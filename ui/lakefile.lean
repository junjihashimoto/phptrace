import Lake
open Lake DSL

package apm where

require «lean-tea» from ".." / "lean-tea"

lean_lib Apm where
  globs := #[.submodules `Apm]

@[default_target]
lean_exe apm_serve where
  root := `Apm.Serve

lean_exe apm_top where
  root := `Apm.Top
