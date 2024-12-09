import React from 'react';

export const InfoContext = React.createContext(null);
export function useInfo() {
    const info = React.useContext(InfoContext);
    return info;
}

export const PageContext = React.createContext(null);
export function usePage() {
    const info = React.useContext(PageContext);
    return info;
}