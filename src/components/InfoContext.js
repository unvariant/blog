import React from 'react';

export const InfoContext = React.createContext(null);
export function useInfo() {
    const info = React.useContext(InfoContext);
    // return React.useMemo(
    //     function () {
    //         return info;
    //     },
    //     [info]
    // );
    return info;
}