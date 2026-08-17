export default function DynamicPage({ params }: { params: { slug: string } }) {
  return <main>{params.slug}</main>;
}
