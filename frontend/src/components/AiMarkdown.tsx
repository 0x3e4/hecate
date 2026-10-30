import Markdown, { type Components } from "react-markdown";

// Reports quote advisory text, so a model can be talked into writing an image whose
// URL carries inventory details. Rendering it would send them out on every view.
const NO_IMAGES = ["img"];

type Props = {
  children: string;
  components?: Components;
};

export function AiMarkdown({ children, components }: Props) {
  return (
    <Markdown disallowedElements={NO_IMAGES} components={components}>
      {children}
    </Markdown>
  );
}
