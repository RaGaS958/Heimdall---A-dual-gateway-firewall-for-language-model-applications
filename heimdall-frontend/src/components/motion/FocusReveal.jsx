/** Rebuilt from Origin Kit focus-reveal's description, in CSS so the hero needs no animation library.
 *  Text is visible from the first frame. `accent` names the words drawn in the threat colour. */
export default function FocusReveal({ as: Tag = 'h1', text, accent = '', className = '' }) {
  let count = 0
  const hot = new Set(accent.split(' ').filter(Boolean))
  return (
    <Tag className={`focus-reveal ${className}`} aria-label={text}>
      <span aria-hidden="true">{text.split(' ').map((word, w, all) => (
        <span className={`fx-word ${hot.has(word) ? 'red' : ''}`} key={w}>{[...word].map((c, i) => <span key={i} style={{ '--i': count++ }}>{c}</span>)}{w < all.length - 1 ? ' ' : ''}</span>
      ))}</span>
    </Tag>
  )
}
